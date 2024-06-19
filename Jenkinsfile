pipeline {
    agent any
    
    stages {
        stage("多仓CI") {
            steps {
                script {
		        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
	                    sh "rm -rf $WORKSPACE/report"
	                    parallel repoJobs()
			}
                }
            }
        }
        stage("合并展示"){
            steps {
                script {
                    echo "-------------------------allure report generating start---------------------------------------------------"
                    sh 'cd $WORKSPACE && allure generate ./report/result -o ./report/html --clean'
                    allure includeProperties: false, jdk: 'jdk17', report: "report/html", results: [[path: "report/result"]]
                    echo "-------------------------allure report generating end ----------------------------------------------------"
                }
            }
        } 
    }
}

def repos() {
  return ["$currentRepoName", "$mainRepoName"]
}

def repoJobs() {
  jobs = [:]
  repos().each { repo ->
    jobs[repo] = { 
        stage(repo + "代码检出"){
           echo "$repo 代码检出"
           sh "rm -rf  $repo; git clone $GITHUB_URL_PREFIX$repo$GITHUB_URL_SUFFIX; echo `pwd`;"
        }
        stage(repo + "编译测试"){
                script {
		        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                           withEnv(["repoName=$repo"]) { // it can override any env variable
                                echo "repoName = ${repoName}"
                                echo "$repo 编译测试"
                                sh 'printenv'
                                sh "cp -r /home/jenkins_home/pytest $WORKSPACE/$repo"
                                echo "--------------------------------------------$repo test start------------------------------------------------"
                                if (repoName == mainRepoName){
                                  sh 'export pywork=$WORKSPACE/${repoName} repoName=${repoName} && cd $pywork/pytest && python3 -m pytest -m mainrepo --cmdrepo=${repoName} -sv --alluredir report/result testcase/test_arceos.py --clean-alluredir'
                                } else {
                                  sh 'export pywork=$WORKSPACE/${repoName} repoName=${repoName} && cd $pywork/pytest && python3 -m pytest -m childrepo --cmdrepo=${repoName} -sv --alluredir report/result testcase/test_arceos.py --clean-alluredir'
                                }
                                echo "--------------------------------------------$repo test end  ------------------------------------------------"
                          }
		       }
               }
        }
        stage(repo + "报告生成"){
            withEnv(["repoName=$repo"]) { // it can override any env variable
                echo "repoName = ${repoName}"
                echo "$repo 报告生成"
                // 输出 Allure 报告地址
                echo "$repo Allure Report URL: ${allureReportUrl}"
                echo "-------------------------$repo allure report generating start---------------------------------------------------"
                sh 'export pywork=$WORKSPACE/${repoName} && cd $pywork/pytest && cp -r ./report $WORKSPACE'
                echo "-------------------------$repo allure report generating end ----------------------------------------------------"
            }
        }
    }
  }
  return jobs
}
