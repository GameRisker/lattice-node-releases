import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import publish

class PublicationTests(unittest.TestCase):
    def test_inventory_rejects_extra_symlink_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            for name in publish.FILES: (Path(d)/name).write_bytes(b'data')
            self.assertEqual(len(publish.inventory(d)),9)
            (Path(d)/'extra').write_bytes(b'x')
            with self.assertRaises(ValueError): publish.inventory(d)
            (Path(d)/'extra').unlink()
            (Path(d)/'install.ps1').unlink()
            (Path(d)/'install.ps1').symlink_to(Path(d)/'release.pub.pem')
            with self.assertRaises(ValueError): publish.inventory(d)
    def test_remote_checksum_and_inventory(self):
        good={'draft':True,'tag_name':'t','assets':[{'name':'a','size':1,'digest':'sha256:x'}]}
        publish.check_remote(good,{'a':(1,'sha256:x')},'t')
        for altered in ({**good,'draft':False},{**good,'tag_name':'wrong'}, {**good,'assets':[]}, {**good,'assets':[{'name':'a','size':1,'digest':'sha256:wrong'}]}):
            with self.assertRaises(ValueError):publish.check_remote(altered,{'a':(1,'sha256:x')},'t')
    def test_existing_tag_cannot_create_release(self):
        tag='v2026.11.13-deepseek-windows-selfuse1'
        with patch.object(publish,'inventory',return_value={}),patch.object(publish,'gh',return_value=('[{"ref":"refs/tags/'+tag+'"}]').encode()) as gh:
            with self.assertRaises(ValueError):publish.publish('/tmp/unused',tag,'a'*40,'b'*40)
            self.assertEqual(gh.call_count,1)
    def test_draft_mismatch_does_not_publish(self):
        tag='v2026.11.13-deepseek-windows-selfuse1'
        with patch.object(publish,'inventory',return_value={'install.ps1':(3,'sha256:x')}), patch.object(publish,'gh',side_effect=[b'[]',b'',b'{"draft":true,"tag_name":"'+tag.encode()+b'","assets":[]}']) as gh:
            with self.assertRaises(ValueError):publish.publish('/tmp/unused',tag,'a'*40,'b'*40)
            self.assertEqual(gh.call_count,3)
            create=gh.call_args_list[1].args
            self.assertEqual(create[create.index('--target')+1],'b'*40)
            self.assertFalse(any(call.args[:2]==('release','edit') for call in gh.call_args_list))
    def test_invalid_tag_no_api(self):
        with patch.object(publish,'gh') as gh:
            with self.assertRaises(ValueError):publish.publish('/unused','../../x','a'*40,'b'*40)
            gh.assert_not_called()
if __name__=='__main__':unittest.main()
