package com.hancomins.util;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;


class JarSignTest {
    @Test
    void test() throws PGPException, IOException, NoSuchAlgorithmException, NoSuchProviderException {

        File dir = new File("res");
        System.out.println(dir.getAbsolutePath());

        if(!dir.isDirectory()) {
            throw new RuntimeException(dir.getAbsolutePath() + " is not a directory");
        }

        Arrays.stream(dir.listFiles()).filter(it -> {
            String name = it.getName();
            return name.endsWith(".asc") || name.endsWith(".pub") || name.endsWith(".md5") || name.endsWith(".sha1") || name.endsWith(".sha256") || name.endsWith(".sha512");
        }).forEach(File::delete);


        try {




            String targetJar = new File(dir, "test.jar").getAbsolutePath();
            String signedJar = new File(dir, "test.gpg").getAbsolutePath();
            String publicKeyPath = new File(dir, "test.pub").getAbsolutePath();
            String keyRingFilePath = new File(dir, "test.gpg").getAbsolutePath();


            List<String> ids  = JarSign.getIdFromKeyRingFilePath(keyRingFilePath);

            JarSign.extractPublicKeys(signedJar, publicKeyPath);




            String keyId = "983D703EF143C7A5";
            String passphrase = "test1234";

            assertTrue(ids.contains(keyId));
            JarSign.sign(targetJar,keyRingFilePath, keyId, passphrase);

            JarSign.verifyAll(targetJar, publicKeyPath);

        } finally {
            Arrays.stream(dir.listFiles()).filter(it -> {
                String name = it.getName();
                return name.endsWith(".asc") || name.endsWith(".pub") || name.endsWith(".md5") || name.endsWith(".sha1") || name.endsWith(".sha256") || name.endsWith(".sha512");
            }).forEach(File::delete);
        }






    }

}