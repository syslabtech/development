import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.projectFeatures.*

object GoBuild : BuildType({
    name = "Build Go Project"

    vcs {
        root(DslContext.settingsRoot)
    }

    steps {
        script {
            name = "Install Dependencies"
            scriptContent = "go mod tidy"
        }
        script {
            name = "Build Application"
            scriptContent = "go build -o app ."
        }
        script {
            name = "Docker Build"
            scriptContent = "docker build -t my-go-app:latest ."
        }
    }

    requirements {
        contains("docker.server.version", "27.") 
    }
})
