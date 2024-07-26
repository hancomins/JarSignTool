package com.hancomins.util;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;


public class JarSign {

    public static final String PROPERTY_KEY_SECRET_KEY_RING_FILE = "jarSign.secretKeyRingFile";
    public static final String PROPERTY_KEY_KEY_ID = "jarSign.keyId";
    public static final String PROPERTY_KEY_PASSPHRASE = "jarSign.passphrase";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private JarSign() {
    }

    /**
     * 파일을 PGP를 사용하여 서명하고, MD5, SHA-1, SHA-256 해시 파일을 생성합니다.<br>
     * 결과로 생성되는 파일:<br>
     *  1. {filePath}.md5: 원본 파일의 MD5 해시 값을 포함하는 파일<br>
     *  2. {filePath}.sha1: 원본 파일의 SHA-1 해시 값을 포함하는 파일<br>
     *  3. {filePath}.sha256: 원본 파일의 SHA-256 해시 값을 포함하는 파일<br>
     *  4. {filePath}.asc: 원본 파일의 PGP 서명 파일<br>
     *
     * @param filePath 서명할 파일의 경로
     * @param secretKeyPath 비밀 키 링 파일의 경로
     * @param keyId 서명에 사용할 키 ID
     * @param passphrase 비밀 키의 패스프레이즈
     * @throws PGPException PGP 작업 중 오류가 발생한 경우
     * @throws IOException 입출력 오류가 발생한 경우
     * @throws NoSuchAlgorithmException 지정된 해시 알고리즘을 사용할 수 없는 경우
     */
    public static void sign(String filePath, String secretKeyPath,String keyId,String passphrase) throws PGPException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        generateMd5File(filePath);
        generateSha1File(filePath);
        generateSha256File(filePath);
        pgpSignFile(filePath, filePath + ".asc", secretKeyPath, keyId, passphrase);
        if(isSignatureComplete(filePath)) {
            String publicKeyPath = filePath + ".pub";
            try {
                extractPublicKeys(secretKeyPath, publicKeyPath);
                if (!verifyAll(filePath, publicKeyPath)) {
                    throw new IllegalStateException("Failed to verify the signature.");
                }
                System.out.println("Signature verification successful: " + filePath);
            } finally {
                //noinspection ResultOfMethodCallIgnored
                new File(publicKeyPath).delete();
            }
        }
    }


    /**
     * 파일을 PGP를 사용하여 서명하고, MD5, SHA-1, SHA-256 해시 파일을 생성합니다.<br>
     * 결과로 생성되는 파일:<br>
     *  1. {filePath}.md5: 원본 파일의 MD5 해시 값을 포함하는 파일<br>
     *  2. {filePath}.sha1: 원본 파일의 SHA-1 해시 값을 포함하는 파일<br>
     *  3. {filePath}.sha256: 원본 파일의 SHA-256 해시 값을 포함하는 파일<br>
     *  4. {filePath}.asc: 원본 파일의 PGP 서명 파일<br>
     *
     * @param filePath 서명할 파일의 경로
     * @param properties 서명에 필요한 설정을 포함하는 Properties 객체<br>
     *                   - jarSign.secretKeyRingFile: 비밀 키 링 파일의 경로<br>
     *                   - jarSign.keyId: 서명에 사용할 키 ID<br>
     *                   - jarSign.passphrase: 비밀 키의 패스프레이즈<br>
     * @throws PGPException PGP 작업 중 오류가 발생한 경우
     * @throws IOException 입출력 오류가 발생한 경우
     * @throws NoSuchAlgorithmException 지정된 해시 알고리즘을 사용할 수 없는 경우
     */
    public static void sign(String filePath, Properties properties) throws PGPException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        String secretKeyPath = properties.getProperty(PROPERTY_KEY_SECRET_KEY_RING_FILE, "");
        String keyId = properties.getProperty(PROPERTY_KEY_KEY_ID, "");
        String passphrase = properties.getProperty(PROPERTY_KEY_PASSPHRASE, "");
        sign(filePath, secretKeyPath, keyId, passphrase);
    }

    /**
     * {@link #sign(String, String, String, String)} 혹은 {@link #sign(String, Properties)} 메서드를 사용하여 서명된 파일의 서명이 완료되었는지 확인합니다.
     * @param filePath
     * @return
     */
    public static boolean isSignatureComplete(String filePath) {
        return new File(filePath + ".asc").exists();
    }


    /**
     * 파일의 MD5, SHA-1, SHA-256 해시 및 PGP 서명을 모두 검증합니다.
     * @param filePath 검증할 파일의 경로
     * @param publicKeyPath 공개 키 파일의 경로
     * @return 모든 검증이 성공하면 true, 그렇지 않으면 false
     * @throws IOException 파일 읽기 중 오류가 발생한 경우
     * @throws NoSuchAlgorithmException 지정된 해시 알고리즘을 사용할 수 없는 경우
     */
    public static boolean verifyAll(String filePath, String publicKeyPath) throws IOException, NoSuchAlgorithmException {
        boolean result = false;
        try {
            result = verifyMd5(filePath) && verifySha1(filePath) && verifySha256(filePath) && verifySignature(publicKeyPath, filePath, filePath + ".asc");
        } catch (PGPException e) {
            e.printStackTrace();
        }
        return result;
    }



    /**
     * 비밀 키 링 파일에서 공개 키를 추출하여 파일로 저장합니다.
     * @param keyRingFilePath 비밀 키 링 파일의 경로
     * @param outputFilePath 추출된 공개 키를 저장할 파일의 경로
     * @throws IOException 파일 읽기 또는 쓰기 중 오류가 발생한 경우
     * @throws PGPException PGP 작업 중 오류가 발생한 경우
     */
    public static void extractPublicKeys(String keyRingFilePath, String outputFilePath) throws IOException, PGPException {
        try (FileInputStream keyIn = new FileInputStream(keyRingFilePath);
             FileOutputStream pubOut = new FileOutputStream(outputFilePath)) {

            // 비밀 키 링 컬렉션을 읽기
            PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            // 비밀 키 링에서 공개 키 추출
            for (Iterator<PGPSecretKeyRing> keyRingIterator = pgpSecretKeyRingCollection.getKeyRings(); keyRingIterator.hasNext();) {
                PGPSecretKeyRing keyRing = keyRingIterator.next();
                for (Iterator<PGPSecretKey> keyIterator = keyRing.getSecretKeys(); keyIterator.hasNext();) {
                    PGPSecretKey secretKey = keyIterator.next();
                    PGPPublicKey publicKey = secretKey.getPublicKey();
                    publicKey.encode(pubOut);
                }
            }
        }
    }



    /**
     * 비밀 키 링 파일에서 키 ID 목록을 추출합니다.
     *
     * @param keyRingFilePath 비밀 키 링 파일의 경로
     * @return 키 ID 목록
     * @throws IOException 파일 읽기 중 오류가 발생한 경우
     * @throws PGPException PGP 작업 중 오류가 발생한 경우
     */
    public static List<String> getIdFromKeyRingFilePath(String keyRingFilePath ) throws IOException, PGPException {
        List<String> result = new ArrayList<>();

        // 비밀 키 링 파일 읽기
        try(FileInputStream keyRingFileStream = new FileInputStream(keyRingFilePath)) {
            PGPSecretKeyRingCollection secretKeyRings = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyRingFileStream), new JcaKeyFingerprintCalculator());

            // 키 링 내의 모든 비밀 키 추출
            Iterator<PGPSecretKeyRing> keyRingIterator = secretKeyRings.getKeyRings();
            while (keyRingIterator.hasNext()) {
                PGPSecretKeyRing keyRing = keyRingIterator.next();
                Iterator<PGPSecretKey> keyIterator = keyRing.getSecretKeys();

                // 각 비밀 키의 키 ID 출력
                while (keyIterator.hasNext()) {
                    PGPSecretKey secretKey = keyIterator.next();
                    long keyId = secretKey.getKeyID();
                    System.out.printf("Key ID: %016X\n", keyId);
                    String keyIDString = String.format("%016X", keyId);
                    result.add(keyIDString);
                }
            }
        }
        return result;
    }



    public static void pgpSignFile(String inputFilePath, String outputFilePath, String secretKeyPath, String keyId, String passphrase) throws IOException, PGPException {
        boolean existSignSources = true;
        if(keyId == null || keyId.isEmpty()) {
            System.err.println("PGP Sign File: ${inputFilePath} => No key ID provided for signing. Skipping PGP signing.");
            existSignSources = false;
        }
        if(passphrase == null || passphrase.isEmpty()) {
            System.err.println("PGP Sign File: ${inputFilePath} => No passphrase provided for signing. Skipping PGP signing.");
            existSignSources = false;
        }
        if(secretKeyPath == null || secretKeyPath.isEmpty()) {
            System.err.println("PGP Sign File: ${inputFilePath} => No secret key ring file provided for signing. Skipping PGP signing.");
            existSignSources = false;
        }
        if(!existSignSources) {
            return;
        }

        if(keyId.length() > 16) {
            keyId = keyId.substring(keyId.length() - 16);
        }
        keyId = keyId.toUpperCase();

        // 비밀 키 링 파일 읽기
        File secretKeyRingFile = new File(secretKeyPath);
        if (!secretKeyRingFile.exists()) {
            throw new IllegalArgumentException("Secret key ring file not found: " + secretKeyRingFile.getAbsolutePath());
        }
        try(FileInputStream keyIn = new FileInputStream(secretKeyPath)) {
            PGPSecretKeyRingCollection pgpSecretKeys = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn),
                    new JcaKeyFingerprintCalculator()
            );

            BigInteger number = new BigInteger(keyId, 16);
            // 비밀 키 추출
            long longKeyId = number.longValue(); // 16진수 키 ID 변환
            PGPSecretKey pgpSecretKey = pgpSecretKeys.getSecretKey(longKeyId);
            if (pgpSecretKey == null) {
                throw new IllegalArgumentException("No secret key found with key ID: "  + keyId);
            }

            PGPPrivateKey privateKey = pgpSecretKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().build())
                            .build(passphrase.toCharArray())
            );

            // 파일 서명

            // 파일 서명
            try (FileInputStream fis = new FileInputStream(inputFilePath);
                 FileOutputStream fos = new FileOutputStream(outputFilePath);
                 ArmoredOutputStream aos = new ArmoredOutputStream(fos)) {

                // 서명 생성기 설정
                PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(pgpSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256)
                                .setProvider("BC"));
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

                // 파일을 읽고 서명 생성
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    signatureGenerator.update(buffer, 0, bytesRead);
                }

                // 서명 데이터를 ArmoredOutputStream에 쓰기
                PGPSignature signature = signatureGenerator.generate();
                signature.encode(aos);
            }
        }
    }



    public static void generateMd5File(String filePath) throws IOException, NoSuchAlgorithmException {
        // 원본 파일의 바이트 배열 읽기
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

        // MD5 해시 계산
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] md5Bytes = md.digest(fileBytes);

        // 바이트 배열을 16진수 문자열로 변환
        StringBuilder md5Hex = new StringBuilder();
        for (byte b : md5Bytes) {
            md5Hex.append(String.format("%02x", b));
        }

        // 결과를 파일명 뒤에 ".md5" 확장자로 붙인 파일에 저장
        String md5FilePath = filePath + ".md5";
        File md5File = new File(md5FilePath);
        Files.writeString(md5File.toPath(), md5Hex.toString());
    }

    public static void generateSha1File(String filePath) throws IOException, NoSuchAlgorithmException {
        // 원본 파일의 바이트 배열 읽기
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

        // SHA-1 해시 계산
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] sha1Bytes = md.digest(fileBytes);

        // 바이트 배열을 16진수 문자열로 변환
        StringBuilder sha1Hex = new StringBuilder();
        for (byte b : sha1Bytes) {
            sha1Hex.append(String.format("%02x", b));
        }

        // 결과를 파일명 뒤에 ".sha1" 확장자로 붙인 파일에 저장
        String sha1FilePath = filePath + ".sha1";
        File sha1File = new File(sha1FilePath);
        Files.writeString(sha1File.toPath(), sha1Hex.toString());
    }

    public static void generateSha256File(String filePath) throws IOException, NoSuchAlgorithmException {
        // 원본 파일의 바이트 배열 읽기
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

        // SHA-256 해시 계산
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] sha256Bytes = md.digest(fileBytes);

        // 바이트 배열을 16진수 문자열로 변환
        StringBuilder sha256Hex = new StringBuilder();
        for (byte b : sha256Bytes) {
            sha256Hex.append(String.format("%02x", b));
        }

        // 결과를 파일명 뒤에 ".sha256" 확장자로 붙인 파일에 저장
        String sha256FilePath = filePath + ".sha256";
        File sha256File = new File(sha256FilePath);
        Files.writeString(sha256File.toPath(), sha256Hex.toString());
    }



    public static boolean verifySignature(String publicKeyFilePath, String signedFilePath, String signatureFilePath) throws IOException, PGPException {
        try (InputStream keyIn = new FileInputStream(publicKeyFilePath);
             InputStream sigIn = PGPUtil.getDecoderStream(new FileInputStream(signatureFilePath));
             InputStream signedDataIn = new FileInputStream(signedFilePath)) {

            // 공개 키 파일에서 공개 키 링 컬렉션을 읽기
            PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            // 서명 객체 생성 및 서명 리스트 가져오기
            PGPObjectFactory pgpFact = new PGPObjectFactory(sigIn, new JcaKeyFingerprintCalculator());
            Object object = pgpFact.nextObject();

            PGPSignatureList sigList = null;
            if (object instanceof PGPCompressedData) {
                PGPCompressedData c1 = (PGPCompressedData) object;
                pgpFact = new PGPObjectFactory(c1.getDataStream(), new JcaKeyFingerprintCalculator());
                sigList = (PGPSignatureList) pgpFact.nextObject();
            } else if (object instanceof PGPSignatureList) {
                sigList = (PGPSignatureList) object;
            }

            if (sigList == null) {
                throw new PGPException("Signature list not found.");
            }

            PGPSignature sig = sigList.get(0);
            PGPPublicKey publicKey = pgpPubRingCollection.getPublicKey(sig.getKeyID());
            if (publicKey == null) {
                throw new PGPException("Public key for the signature not found.");
            }

            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

            // 서명된 데이터를 읽으면서 서명을 검증
            int ch;
            while ((ch = signedDataIn.read()) >= 0) {
                sig.update((byte) ch);
            }

            return sig.verify();
        }
    }



    public static boolean verifyMd5(String filePath) throws IOException, NoSuchAlgorithmException {
        String expectedMd5 = Files.readString(Paths.get(filePath + ".md5"));
        return verifyHash(filePath, expectedMd5, "MD5");
    }

    public static boolean verifySha1(String filePath) throws IOException, NoSuchAlgorithmException {
        String expectedSha1 = Files.readString(Paths.get(filePath + ".sha1"));
        return verifyHash(filePath, expectedSha1, "SHA-1");
    }

    public static boolean verifySha256(String filePath) throws IOException, NoSuchAlgorithmException {
        String expectedSha256 = Files.readString(Paths.get(filePath + ".sha256"));
        return verifyHash(filePath, expectedSha256, "SHA-256");
    }

    public static boolean verifyMd5(String filePath, String expectedMd5) throws IOException, NoSuchAlgorithmException {
        return verifyHash(filePath, expectedMd5, "MD5");
    }

    public static boolean verifySha1(String filePath, String expectedSha1) throws IOException, NoSuchAlgorithmException {
        return verifyHash(filePath, expectedSha1, "SHA-1");
    }

    public static boolean verifySha256(String filePath, String expectedSha256) throws IOException, NoSuchAlgorithmException {
        return verifyHash(filePath, expectedSha256, "SHA-256");
    }




    private static boolean verifyHash(String filePath, String expectedHash, String algorithm) throws IOException, NoSuchAlgorithmException {
        // 파일의 바이트를 읽기
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

        // 지정된 해시 알고리즘을 사용하여 파일의 해시 계산
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] fileHashBytes = digest.digest(fileBytes);

        // 계산된 해시를 16진수 문자열로 변환
        StringBuilder fileHashHex = new StringBuilder();
        for (byte b : fileHashBytes) {
            fileHashHex.append(String.format("%02x", b));
        }

        // 계산된 해시와 기대하는 해시를 비교
        return fileHashHex.toString().equalsIgnoreCase(expectedHash);
    }
}
