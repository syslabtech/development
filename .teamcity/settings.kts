import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.projectFeatures.*

project {
    buildType(GoBuild)
}

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
            name = "Run Tests"
            scriptContent = "go test ./..."
        }
        script {
            name = "Docker Build"
            scriptContent = "docker build -t my-go-app:latest ."
        }
    }

    triggers {
        vcs {
            branchFilter = "+:*"
        }
    }
})
