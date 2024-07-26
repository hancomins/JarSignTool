package com.hancomins.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PomBuilderTest {

    @Test
    void test() {


        PomBuilder.Developer developer = PomBuilder.newDeveloper("Sungbeom Hong")
                .setEmail("ice3x2@gmail.com")
                .setOrganization("HANCOM INNOSTREAM")
                .setOrganizationUrl("https://github.com/hancomins").setId("ice3x2");

        PomBuilder.SCM scm = PomBuilder.newSCM("hancomins/LogExpress");

        String pom = PomBuilder.builder().setGroupId("com.hancomins")
                .setArtifactId("logexpress")
                .setVersion("1.0.0")
                .setName("LogExpress")
                .setUrl("https://github.com/hancomins/LogExpress")
                        .addDeveloper(developer)
                                .setScm(scm)
                .build();


        System.out.println(pom);

    }

}