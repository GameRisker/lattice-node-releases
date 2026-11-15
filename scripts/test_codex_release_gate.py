import copy
import unittest
from codex_release_gate import validate_environment, validate_context, OWNER_ID, REPO

ENV = {'name':'codex-unix-sign','can_admins_bypass':False,
       'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True},
       'protection_rules':[{'type':'branch_policy'}, {'type':'required_reviewers','prevent_self_review':False,
       'reviewers':[{'type':'User','reviewer':{'login':'GameRisker','id':OWNER_ID}}]}]}
POLICIES={'total_count':1,'branch_policies':[{'name':'main','type':'branch'}]}
CONTEXT={'GITHUB_REPOSITORY':REPO,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
         'GITHUB_RUN_ATTEMPT':'1','REVIEWED_WORKFLOW_SHA':'a'*40,'GITHUB_SHA':'a'*40,'REQUEST_PUBLICATION':'false'}
class GateTests(unittest.TestCase):
    def test_good_environment(self): validate_environment(ENV,POLICIES,'codex-unix-sign')
    def test_weakened_environment(self):
        for changes in ({'can_admins_bypass':True},{'protection_rules':[{'type':'branch_policy'}]},
                        {'name':'deepseek-windows-sign'},{'deployment_branch_policy':None}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                validate_environment({**ENV,**changes},POLICIES,'codex-unix-sign')
        for field,value in [('prevent_self_review',True),('reviewers',[])]:
            env=copy.deepcopy(ENV);env['protection_rules'][1][field]=value
            with self.assertRaises(ValueError):validate_environment(env,POLICIES,'codex-unix-sign')
        env=copy.deepcopy(ENV);env['protection_rules'][1]['reviewers'].append({'type':'User','reviewer':{'login':'other','id':2}})
        with self.assertRaises(ValueError):validate_environment(env,POLICIES,'codex-unix-sign')
    def test_branch_namespace(self):
        for policy in ({'total_count':2,'branch_policies':POLICIES['branch_policies']},
                       {'total_count':1,'branch_policies':[{'name':'main','type':'tag'}]},
                       {'total_count':1,'branch_policies':[{'name':'*','type':'branch'}]}):
            with self.assertRaises(ValueError):validate_environment(ENV,policy,'codex-unix-sign')
    def test_context(self):
        validate_context(CONTEXT)
        for field,value in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_REF','refs/tags/main'),('GITHUB_EVENT_NAME','pull_request'),('GITHUB_SHA','b'*40),('REQUEST_PUBLICATION','true')]:
            with self.assertRaises(ValueError):validate_context({**CONTEXT,field:value})
    def test_publication_binding(self):
        env={**CONTEXT,'REQUEST_PUBLICATION':'true','RELEASE_TAG':'tag','SOURCE_SHA':'b'*40,'ARTIFACT_SHA256':'c'*64}
        env['OWNER_RELEASE_APPROVAL']='publish:tag:'+env['SOURCE_SHA']+':'+env['ARTIFACT_SHA256']
        validate_context(env)
        with self.assertRaises(ValueError):validate_context({**env,'ARTIFACT_SHA256':'d'*64})
if __name__=='__main__':unittest.main()
