import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import publish_codex as publish

class PublicationTests(unittest.TestCase):
    def test_inventory_rejects_extra_symlink_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            for name in publish.FILES: (Path(d)/name).write_bytes(b'data')
            self.assertEqual(len(publish.inventory(d)),13)
            (Path(d)/'extra').write_bytes(b'x')
            with self.assertRaises(ValueError): publish.inventory(d)
            (Path(d)/'extra').unlink()
            (Path(d)/'install.sh').unlink()
            (Path(d)/'install.sh').symlink_to(Path(d)/'release.pub.pem')
            with self.assertRaises(ValueError): publish.inventory(d)
    def test_remote_checksum_and_inventory(self):
        good={'draft':True,'tag_name':'t','assets':[{'name':'a','size':1,'digest':'sha256:x'}]}
        publish.check_remote(good,{'a':(1,'sha256:x')},'t')
        for altered in ({**good,'draft':False},{**good,'tag_name':'wrong'}, {**good,'assets':[]}, {**good,'assets':[{'name':'a','size':1,'digest':'sha256:wrong'}]}):
            with self.assertRaises(ValueError):publish.check_remote(altered,{'a':(1,'sha256:x')},'t')
    def test_existing_tag_cannot_create_release(self):
        tag='v2026.11.15-codex-unix-root2-1'
        with patch.object(publish,'load_verified_inventory',return_value={}),patch.object(publish,'inventory',return_value={}),patch.object(publish,'gh',return_value=('[{"ref":"refs/tags/'+tag+'"}]').encode()) as gh:
            with self.assertRaises(ValueError):publish.publish('/tmp/unused',tag,'a'*40,'b'*40,'/tmp/verified')
            self.assertEqual(gh.call_count,1)
    def test_draft_mismatch_does_not_publish(self):
        tag='v2026.11.15-codex-unix-root2-1'
        with patch.object(publish,'load_verified_inventory',return_value={'install.sh':(3,'sha256:x')}),patch.object(publish,'inventory',return_value={'install.sh':(3,'sha256:x')}), patch.object(publish,'gh',side_effect=[b'[]',b'',b'{"draft":true,"tag_name":"'+tag.encode()+b'","assets":[]}']) as gh:
            with self.assertRaises(ValueError):publish.publish('/tmp/unused',tag,'a'*40,'b'*40,'/tmp/verified')
            self.assertEqual(gh.call_count,3)
            create=gh.call_args_list[1].args
            self.assertEqual(create[create.index('--target')+1],'b'*40)
            self.assertIn('--latest=false',create)
            self.assertFalse(any(call.args[:2]==('release','edit') for call in gh.call_args_list))
    def test_success_keeps_legacy_latest_unchanged(self):
        import json
        tag='v2026.11.15-codex-unix-root2-1'
        expected={name:(3,'sha256:'+'a'*64) for name in publish.FILES}
        draft={'id':9,'draft':True,'tag_name':tag,'assets':[{'name':name,'size':size,'digest':digest} for name,(size,digest) in expected.items()]}
        final={**draft,'draft':False}
        with patch.object(publish,'load_verified_inventory',return_value=expected),patch.object(publish,'inventory',return_value=expected),patch.object(publish,'gh',side_effect=[b'[]',b'',json.dumps(draft).encode(),b'',json.dumps(final).encode()]) as gh:
            publish.publish('/tmp/unused',tag,'a'*40,'b'*40,'/tmp/verified')
            self.assertIn('--latest=false',gh.call_args_list[1].args)
            self.assertIn('--latest=false',gh.call_args_list[3].args)
            self.assertFalse(any('--clobber' in call.args for call in gh.call_args_list))
    def test_changed_verified_package_no_api(self):
        with patch.object(publish,'load_verified_inventory',return_value={'install.sh':(3,'sha256:approved')}),patch.object(publish,'inventory',return_value={'install.sh':(3,'sha256:changed')}),patch.object(publish,'gh') as gh:
            with self.assertRaises(ValueError):publish.publish('/unused','v2026.11.15-codex-unix-root2-1','a'*40,'b'*40,'/verified')
            gh.assert_not_called()
    def test_verifier_inventory_format(self):
        import json
        data={name:{'size':3,'sha256':'a'*64} for name in publish.FILES}
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'inventory.json'
            path.write_text(json.dumps(data))
            self.assertEqual(set(publish.load_verified_inventory(path)),publish.FILES)
            data['install.sh']['size']=True
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):publish.load_verified_inventory(path)
    def test_invalid_tag_no_api(self):
        with patch.object(publish,'gh') as gh:
            with self.assertRaises(ValueError):publish.publish('/unused','../../x','a'*40,'b'*40,'/tmp/verified')
            gh.assert_not_called()
if __name__=='__main__':unittest.main()
