#!groovy
node { 
	def PRODUCT_NAME=env.JOB_NAME.toLowerCase()
	String IMAGE_NAME="${PRODUCT_NAME}"
	String PORT='9002'
	String GIT_URL = 'https://github.com/liangx8892/' + IMAGE_NAME + '.git'
	String DOCKER_REPO="registry.cn-shenzhen.aliyuncs.com/liangx8892"
	String DOCKER_REG="https://" + DOCKER_REPO + "/"
	String REG_CREDENTIAL_ID = "9caf828c-33c7-4dda-9abe-e7e186274d74"
	String GITHUB_CREDENTIAL_ID = "76777026-0e96-4a3c-a336-1a2fd16e442b"
	
	String IMAGE_TAG=env.BUILD_NUMBER
	String REMOVE_COMMAND='docker rm -f ' + IMAGE_NAME
	String RUN_ARGS='--name ' + IMAGE_NAME + ' -p ' + PORT + ':' + PORT
	
	def customImage
	
    stage('Checkout code base') {
        checkout([$class: 'GitSCM', branches: [[name: '*/master']], 
        		doGenerateSubmoduleConfigurations: false, 
        		extensions: [], 
        		submoduleCfg: [], 
        		userRemoteConfigs: [[credentialsId: GITHUB_CREDENTIAL_ID, url: GIT_URL]]])
    }

    stage('Build Spring boot web application') {
		sh 'mvn clean install'
    }
    
    stage('Build and push docker image') {
        echo 'Building docker image which contains jar package.'
        docker.withRegistry(DOCKER_REG,REG_CREDENTIAL_ID){
      		customImage = docker.build(DOCKER_REPO + "/" + IMAGE_NAME)    
      		customImage.tag(IMAGE_TAG)
    	}
    }
    
    stage('Deploy as docker container') {
    	sh REMOVE_COMMAND
    	customImage.run(RUN_ARGS)
    }
}
