from pathlib import Path
import re
import unittest

class WorkflowContractTests(unittest.TestCase):
    def test_secret_and_publication_boundaries(self):
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/codex-unix-release.yml').read_text()
        self.assertIn('default: false',text)
        self.assertEqual(text.count('secrets.CODEX_ROOT2_PRIVATE_KEY'),1)
        self.assertIn('--key-env CODEX_ROOT2_PRIVATE_KEY',text)
        self.assertNotIn('echo "$CODEX_ROOT2_PRIVATE_KEY"',text)
        self.assertNotIn('actions/setup-go',text)
        self.assertIn('environment: codex-unix-sign',text)
        self.assertIn('environment: codex-unix-publish',text)
        self.assertIn('OWNER_RELEASE_APPROVAL',text)
        self.assertIn('--check-archive',text)
        self.assertIn('artifact-ids: ${{ needs.sign.outputs.package_id }}',text)
        self.assertIn('if: inputs.publish',text)
        for action in re.findall(r'uses: (.+)',text):
            self.assertRegex(action,r'^actions/[a-z-]+@[a-f0-9]{40}$')
        publish=text.split('\n  publish:\n',1)[1]
        self.assertNotIn('secrets.',publish)
        self.assertIn('--verify-dir',publish)
        self.assertIn('contents: write',publish)
        self.assertNotIn('contents: write',text.split('\n  publish:\n',1)[0])
        self.assertIn('python3 scripts/codex_release_gate.py --environment codex-unix-publish',publish)
if __name__=='__main__':unittest.main()
