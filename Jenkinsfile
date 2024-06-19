pipeline {
    agent any

    stages {
        stage('Deploy') {
            steps {
                // 进行部署，这里只是一个示例，具体部署步骤根据你的实际需求编写
                echo 'Deploying to the server...'
            }
        }
    }

    post {
        // 无论构建成功与否，都发送通知
        always {
            echo 'Pipeline finished.'
        }
        // 构建失败时发送通知
        failure {
            echo 'Pipeline failed!'
        }
    }
}
