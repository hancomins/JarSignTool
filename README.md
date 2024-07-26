# JAR 파일 서명을 위한 GPG 키 생성 및 사용

GPG 키를 생성하고 이를 사용하여 JAR 파일을 서명하는 방법을 단계별로 설명합니다. 이 과정은 GPG 키 생성, 공개 키 등록, JAR 파일 서명, 서명된 JAR 파일 검증의 단계로 구성됩니다.

### 1. GPG 설치
GPG를 설치합니다. GPG는 GNU Privacy Guard의 약자로, 개인 정보 보호를 위한 오픈 소스 암호화 소프트웨어입니다.
```shell
# Ubuntu, Debian
sudo apt-get install gnupg
# CentOS, Fedora, RHEL
sudo yum install gnupg
```

## 2. GPG 키 생성

GPG 키는 개인 키와 공개 키 쌍으로 구성됩니다. 개인 키는 서명에 사용되며, 공개 키는 서명 검증에 사용됩니다.

### GPG 키 생성 명령어

```bash
gpg --full-generate-key
```

### 키 생성 과정
1. 키 유형 선택: RSA and RSA (default)를 선택합니다.  (엔터 입력하여 기본 값 선택)
2. 키 크기 선택: 보안을 위해 4096비트 이상의 키 크기를 선택합니다.(4096 직접 입력)
3. 키 만료 기간 설정: 필요한 경우 키의 만료 기간을 설정합니다.  (0: 만료 없음 선택)
4. 사용자 정보 입력: 이름, 이메일 주소, 주석 등을 입력합니다. (이메일 주소는 키 ID를 확인할 때 사용됩니다.)
5. 패스프레이즈 설정: 개인 키 보호를 위한 패스프레이즈(패스워드)를 설정합니다. 
6. 키가 생성되면 키 ID가 표시됩니다.


## 2. GPG 키, ID 확인 
1. GPG 키 목록을 확인합니다.
    ```bash
    # 비밀키 목록 확인, 키 생성에 사용된 이메일 주소를 입력합니다.
    gpg --list-secret-keys "yourName@domain.com"
    ```
2. GPG 키 ID 확인
    ```bash
    sec   rsa4096 2024-07-26 [SC]
          4E55EFDAD28AEF3E78A5027E983D703EF143C7A5
    uid           [ultimate] YourName <YourName@domain.com>
    ssb   rsa4096 2024-07-26 [E]
    ```
    - 위 예시에서 `4E55EFDAD28AEF3E78A5027E983D703EF143C7A5`가 키 ID입니다.
    - 뒤에 16자리 키 ID를 사용하여 공개키를 등록하고, JAR 파일 서명에 사용합니다. (983D703EF143C7A5)

## 3. GPG 공개 키 등록
 - 위 과정에서 생성한 GPG 공개 키를 keyserver에 등록합니다.
 - ID 값을 사용하여 공개 키를 등록합니다.
    ```bash
    gpg --keyserver keyserver.ubuntu.com --send-keys 983D703EF143C7A5
    ```
   
## 4. 비밀키 파일 내보내기
- 비밀키를 파일로 내보내기 합니다. 
    ```bash
    gpg --export-secret-keys 983D703EF143C7A5 > test.gpg
    ```
    
## 4. JarSignTool 도구를 이용하여 gradle 에서 JAR 파일 서명과 검증 및 hash 생성
    ```groovy
    # build.gradle 파일에 JarSignTool 플러그인 추가
      buildscript {

         dependencies {
            $ boucycastle 라이브러리 추가
            classpath 'org.bouncycastle:bcpg-jdk15on:1.70'
            classpath 'org.bouncycastle:bcpg-jdk15on:1.70'
   
            def path = "JarSignTool 라이브러리가 있는 경로"
            classpath fileTree(dir:path, include: ['*.jar'])
       }
      }

     import com.hancomins.util.JarSign
     import com.hancomins.util.PomBuilder

      # 중략...

      
      jar {
      
          manifest {
              attributes(
                        'Implementation-Title': 'test',
                        'Implementation-Version': version,
                        'Main-Class': 'com.hancomins.Main'
              )
          }
      
          doLast {
              def jarFilePath = archiveFile.get().asFile.path
              # jar 파일이 만들어진 경로 디렉토리에 .asc, .md5, .sha256, .sha1 파일이 생성됩니다.
              def secretKeyRingFile = "비밀키 파일 경로"
              def keyId = "키 ID"
              def keyPass = "비밀키 패스워드"
              JarSign.sign(jarFilePath, secretKeyRingFile, keyId, keyPass);
              # Properties 를 사용할 수도 있습니다.
              # jarSign.secretKeyRingFile=비밀키 파일 경로
              # jarSign.keyId=키 ID
              # jarSign.passphrase=비밀키 패스워드
              # jarSign.sign(jarFilePath, properties객체);
          }
      }

      # pom.xml 파일 생성
      task makePom {
         group = 'build'
         doLast {
         def pomFilePath = "${buildDir}/libs/test_tool-${version}.pom"
         
                 PomBuilder.builder()
                 PomBuilder.Developer developer = PomBuilder.newDeveloper("이름")
                         .setEmail("이메일")
                         .setOrganization("HANCOM INNOSTREAM")
                         .setOrganizationUrl("https://github.com/hancomins").setId("아이디");
         
                 PomBuilder.SCM scm = PomBuilder.newSCM("깃 허브 path");
         
                 PomBuilder.builder().setGroupId("그룹 ID")
                         .setArtifactId("아티팩트 ID")
                         .setVersion("${version}")
                         .setName("프로젝트 이름")
                         .setUrl("이름")
                         .addDeveloper(developer)
                         .setScm(scm)
                         .writeFile(pomFilePath);
         
                 JarSign.sign(pomFilePath, signProperties);
             }
      }
    ```
            

            
    
