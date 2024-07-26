package com.hancomins.util;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Data
@Accessors(chain = true)
public class PomBuilder {

    @Setter(AccessLevel.NONE)
    @Getter(AccessLevel.NONE)
    private StringBuilder builder = new StringBuilder();
    @Setter(AccessLevel.NONE)
    @Getter(AccessLevel.NONE)
    public static final String MODEL_VERSION = "4.0.0";

    private String groupId;
    private String artifactId;
    private String version;
    private String packaging = "jar";

    private String name;
    private String description = "";
    private String url;
    private String javaVersion = "1.8";

    private String licenseName = "The Apache Software License, Version 2.0";
    private String licenseUrl = "http://www.apache.org/licenses/LICENSE-2.0.txt";


    @Setter(AccessLevel.NONE)
    @Getter(AccessLevel.NONE)
    private List<Dependency> dependencies = new ArrayList<>();
    @Setter(AccessLevel.NONE)
    @Getter(AccessLevel.NONE)
    private List<Developer> developer = new ArrayList<>();
    private SCM scm = null;

    public PomBuilder addDependency(String groupId, String artifactId, String version) {
        Dependency dependency = new Dependency(groupId, artifactId, version);
        dependencies.add(dependency);
        return this;
    }

    public PomBuilder addDependency(Dependency dependency) {
        dependencies.add(dependency);
        return this;
    }

    public PomBuilder addDeveloper(Developer developer) {
        this.developer.add(developer);
        return this;
    }




    public void writeFile(String path) throws IOException {
        String pom = toString();
        Files.write(Paths.get(path), pom.getBytes());
    }

    public static PomBuilder builder() {
        return new PomBuilder();
    }

    public static Developer newDeveloper(String name) {
        return new Developer(name);
    }

    public static Dependency newDependency(String groupId, String artifactId, String version) {
        return new Dependency(groupId, artifactId, version);
    }

    public static SCM newSCM(String githubPath) {
        return SCM.fromGitHub(githubPath);
    }

    public static SCM newSCM(String connection, String developerConnection, String url) {
        return new SCM(connection, developerConnection, url);
    }




    private PomBuilder() {
    }

    public String toString() {
        return build();
    }

    public String build() {
        builder.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        builder.append("<project xmlns=\"http://maven.apache.org/POM/4.0.0\"\n");
        builder.append("         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n");
        builder.append("         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n");
        builder.append("    <modelVersion>").append(MODEL_VERSION).append("</modelVersion>\n");
        if(groupId == null || artifactId == null || version == null || name == null || url == null || groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty() || name.isEmpty() || url.isEmpty() ){
            throw new IllegalArgumentException("'groupId', 'artifactId', 'version', 'name', 'url' is required");
        }
        builder.append("    <groupId>").append(groupId).append("</groupId>\n");
        builder.append("    <artifactId>").append(artifactId).append("</artifactId>\n");
        builder.append("    <version>").append(version).append("</version>\n");
        builder.append("    <packaging>").append(packaging).append("</packaging>\n");
        builder.append("    <name>").append(name).append("</name>\n");
        if(description == null) {
            description = "";
        }
        builder.append("    <description>").append(description).append("</description>\n");
        builder.append("    <url>").append(url).append("</url>\n");
        if(javaVersion != null) {
            builder.append("    <properties>\n");
            builder.append("        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n");
            builder.append("        <maven.compiler.source>").append(javaVersion).append("</maven.compiler.source>\n");
            builder.append("        <maven.compiler.target>").append(javaVersion).append("</maven.compiler.target>\n");
            builder.append("    </properties>\n");
        }
        builder.append("    <licenses>\n");
        builder.append("        <license>\n");
        builder.append("            <name>").append(licenseName).append("</name>\n");
        builder.append("            <url>").append(licenseUrl).append("</url>\n");
        builder.append("        </license>\n");
        builder.append("    </licenses>\n");
        if(developer != null) {
            builder.append("    <developers>\n");
            for(Developer developer : developer) {
                builder.append(developer.toString());
            }
            builder.append("    </developers>\n");
        } else {
            throw new IllegalArgumentException("'developer' is required");
        }

        builder.append("    <dependencies>\n");
        for(Dependency dependency : dependencies) {
            builder.append(dependency.toString());
        }
        builder.append("    </dependencies>\n");
        if(scm != null) {
            builder.append(scm.toString());
        } else {
            throw new IllegalArgumentException("'scm' is required");
        }
        builder.append("</project>\n");
        return builder.toString();


    }


    private enum MavenDependencyType {
        JAR("jar"),          // 기본값
        POM("pom"),
        WAR("war"),
        EAR("ear"),
        TEST_JAR("test-jar"),
        EJB("ejb"),
        MAVEN_PLUGIN("maven-plugin"),
        BUNDLE("bundle");

        private final String type;

        MavenDependencyType(String type) {
            this.type = type;
        }

        public String getType() {
            return type;
        }

        @Override
        public String toString() {
            return type;
        }
    }

    @Data
    @Accessors(chain = true)
    public static class Dependency {
        private String groupId;
        private String artifactId;
        private String version;
        private String scope;
        private MavenDependencyType type = MavenDependencyType.JAR;
        private String classifier;
        private String systemPath;
        private String optional;

        Dependency(String groupId, String artifactId, String version) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.version = version;
        }

        public String toString() {
            if(groupId == null || artifactId == null || version == null || groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty()) {
                throw new IllegalArgumentException("Dependency 'groupId', 'artifactId', 'version' is required");
            }


            StringBuilder builder = new StringBuilder();
            builder.append("    <dependency>\n");
            builder.append("        <groupId>").append(groupId).append("</groupId>\n");
            builder.append("        <artifactId>").append(artifactId).append("</artifactId>\n");
            builder.append("        <version>").append(version).append("</version>\n");
            if(scope != null) {
                builder.append("        <scope>").append(scope).append("</scope>\n");
            }
            if(type != null) {
                builder.append("        <type>").append(type.getType()).append("</type>\n");
            }
            if(classifier != null) {
                builder.append("        <classifier>").append(classifier).append("</classifier>\n");
            }
            if(systemPath != null) {
                builder.append("        <systemPath>").append(systemPath).append("</systemPath>\n");
            }
            if(optional != null) {
                builder.append("        <optional>").append(optional).append("</optional>\n");
            }
            builder.append("    </dependency>\n");
            return builder.toString();
        }


    }

    @Data
    @Accessors(chain = true)
    public static class Developer {
        private String id;
        private String name;
        private String email;
        private String url;
        private String organization;
        private String organizationUrl;

        public Developer(String name) {
            Objects.requireNonNull(name, "Developer 'name' is required");
            if(name.isEmpty()) {
                throw new IllegalArgumentException("Developer 'name' is required");
            }
            this.name = name;
        }

        @Override
        public String toString() {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("    <developer>\n");
            if(id != null) {
                stringBuilder.append("        <id>").append(id).append("</id>\n");
            }
            if(name != null) {
                stringBuilder.append("        <name>").append(name).append("</name>\n");
            }
            if(email != null) {
                stringBuilder.append("        <email>").append(email).append("</email>\n");
            }
            if(url != null) {
                stringBuilder.append("        <url>").append(url).append("</url>\n");
            }
            if(organization != null) {
                stringBuilder.append("        <organization>").append(organization).append("</organization>\n");
            }
            if(organizationUrl != null) {
                stringBuilder.append("        <organizationUrl>").append(organizationUrl).append("</organizationUrl>\n");
            }
            stringBuilder.append("    </developer>\n");
            return stringBuilder.toString();
        }
    }


    @Data
    @Accessors(chain = true)
    public static class SCM {
        private String connection;
        private String developerConnection;
        private String url;

        public SCM(String connection, String developerConnection, String url) {
            this.connection = connection;
            this.developerConnection = developerConnection;
            this.url = url;
        }

        public static SCM fromGitHub(String projectPath) {
            if(!projectPath.startsWith("/")) {
                projectPath = "/" + projectPath;
            }
            return new SCM("scm:git:git://github.com" + projectPath + ".git",
                    "scm:git:ssh://github.com" + projectPath + ".git",
                    "https://github.com" + projectPath);

        }


        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("<scm>\n");
            builder.append("    <connection>").append(connection).append("</connection>\n");
            builder.append("    <developerConnection>").append(developerConnection).append("</developerConnection>\n");
            builder.append("    <url>").append(url).append("</url>\n");
            builder.append("</scm>\n");
            return builder.toString();
        }
    }

}
