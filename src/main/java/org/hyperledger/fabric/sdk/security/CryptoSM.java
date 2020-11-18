package org.hyperledger.fabric.sdk.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.ECPrivateKey;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author Bryan
 * @date 2020-01-16
 */
public class CryptoSM implements CryptoSuite {

    private static final String SecurityProviderClassName = BouncyCastleProvider.class.getName();

    private static final Log logger = LogFactory.getLog(CryptoSM.class);
    private static final Config config = Config.getConfig();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL ? config.getDiagnosticFileDumper() : null;

    public static final SM2P256V1Curve CURVE = new SM2P256V1Curve();
    public final static BigInteger SM2_ECC_N = CURVE.getOrder();
    public final static BigInteger SM2_ECC_H = CURVE.getCofactor();
    public final static BigInteger SM2_ECC_GX = new BigInteger(
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    public final static BigInteger SM2_ECC_GY = new BigInteger(
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    public static final ECPoint G_POINT = CURVE.createPoint(SM2_ECC_GX, SM2_ECC_GY);
    public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT, SM2_ECC_N, SM2_ECC_H);

    private static final String ALGO_NAME_EC = "EC";
    private static final String CERTIFICATE_FORMAT = "X.509";

    private final Provider SECURITY_PROVIDER;
    private final AtomicBoolean inited;

    private String hashAlgorithm = config.getHashAlgorithm();
    private CertificateFactory cf;

    private KeyStore trustStore = null;

    public CryptoSM() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        this.inited = new AtomicBoolean(false);
        String securityProviderClassName = config.getSecurityProviderClassName();
        this.SECURITY_PROVIDER = setUpExplicitProvider(securityProviderClassName);
        if (this.SECURITY_PROVIDER == null) {
            throw new InstantiationException("SECURITY_PROVIDER is null");
        } else {
            Security.addProvider(this.SECURITY_PROVIDER);
        }
    }

    public void init() throws CryptoException, InvalidArgumentException {
        if (this.inited.getAndSet(true)) {
            throw new InvalidArgumentException("Crypto suite already initialized");
        } else {
            this.resetConfiguration();
        }
    }

    private void resetConfiguration() throws CryptoException {
        try {
            this.cf = CertificateFactory.getInstance(this.CERTIFICATE_FORMAT, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchProviderException | CertificateException e) {
            CryptoException ex = new CryptoException(
                    "Cannot initialize  certificate factory. Error = " + e.getMessage(), e);
            logger.error(ex.getMessage());
            throw ex;
        }
    }

    void setProperties(Properties properties) throws CryptoException, InvalidArgumentException {
        if (properties == null) {
            throw new InvalidArgumentException("properties must not be null");
        } else {
            this.hashAlgorithm = Optional
                    .ofNullable(properties.getProperty("org.hyperledger.fabric.sdk.hash_algorithm"))
                    .orElse(this.hashAlgorithm);
            this.resetConfiguration();
        }
    }

    private static Provider setUpExplicitProvider(String securityProviderClassName)
            throws InstantiationException, ClassNotFoundException, IllegalAccessException {
        if (null == securityProviderClassName) {
            throw new InstantiationException(
                    String.format("Security provider class name property (%s) set to null.",
                            "org.hyperledger.fabric.sdk.security_provider_class_name"));
        } else if ("org.hyperledger.fabric.sdk.security.default_jdk_provider".equals(securityProviderClassName)) {
            return null;
        } else {
            Class aClass = null;
            try {
                securityProviderClassName = checkSecurityProviderClassName(securityProviderClassName);
                aClass = Class.forName(securityProviderClassName);
            } catch (Exception e) {
                logger.error(String.format("load securityProviderClassName err: %s", e.getMessage()));
                throw new ClassNotFoundException(
                        String.format("load securityProviderClassName err: %s", e.getMessage()));
            }

            if (null == aClass) {
                throw new InstantiationException("Getting class for security provider returned null");
            } else if (!Provider.class.isAssignableFrom(aClass)) {
                throw new InstantiationException(
                        String.format("Class for security provider %s is not a Java security provider", aClass.getName()));
            } else {
                Provider securityProvider = (Provider) aClass.newInstance();
                return securityProvider;
            }
        }
    }

    @Override
    public CryptoSuiteFactory getCryptoSuiteFactory() {
        return HLSDKJCryptoSuiteFactory.instance();
    }

    @Override
    public Properties getProperties() {
        Properties properties = new Properties();
        properties.setProperty("org.hyperledger.fabric.sdk.hash_algorithm", hashAlgorithm);
        int securityLevel = 256;
        properties.setProperty("org.hyperledger.fabric.sdk.security_level", Integer.toString(securityLevel));
        properties.setProperty("org.hyperledger.fabric.sdk.crypto.certificate_format", CERTIFICATE_FORMAT);
        return properties;
    }

    @Override
    public KeyPair keyGen() {
        KeyPair keyPair = null;
        try {
            SecureRandom random = new SecureRandom();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME);
            ECParameterSpec parameterSpec = new ECParameterSpec(DOMAIN_PARAMS.getCurve(), DOMAIN_PARAMS.getG(),
                    DOMAIN_PARAMS.getN(), DOMAIN_PARAMS.getH());
            kpg.initialize(parameterSpec, random);
            keyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    public ECPrivateKeyParameters getPrivateKey(PrivateKey key) {
        ECPrivateKey ecprivateKey = (ECPrivateKey) key;
        BigInteger d = ecprivateKey.getS();
        ECDomainParameters params = DOMAIN_PARAMS;
        ECPrivateKeyParameters prikey = new ECPrivateKeyParameters(d, params);
        return prikey;
    }

    public ECPublicKeyParameters getPublicKey(PublicKey key) {
        BCECPublicKey ecpublicKey = (BCECPublicKey) key;
        ECDomainParameters params = DOMAIN_PARAMS;
        ECPublicKeyParameters pubkey = new ECPublicKeyParameters(
                CURVE.createPoint(ecpublicKey.getW().getAffineX(), ecpublicKey.getW().getAffineY()), params);
        return pubkey;
    }

    @Override
    public byte[] sign(PrivateKey key, byte[] plainText) throws CryptoException {
        logger.debug("SM Signature");
        return sign(getPrivateKey(key), plainText);
    }

    public byte[] sign(ECPrivateKeyParameters key, byte[] plainText) throws CryptoException {
        return this.sign(key, plainText, null);
    }

    public byte[] sign(ECPrivateKeyParameters key, byte[] plainText, byte[] withId) throws CryptoException {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        ParametersWithRandom pwr = new ParametersWithRandom(key, new SecureRandom());
        if (withId != null) {
            param = new ParametersWithID(pwr, withId);
        } else {
            param = pwr;
        }

        signer.init(true, param);
        //配置fabric中验签，fabric源码中identity模块Verify方法将msg摘要后再验签
        plainText = hash(plainText);
        signer.update(plainText, 0, plainText.length);

        try {
            byte[] sigdata = signer.generateSignature();
            return sigdata;
        } catch (org.bouncycastle.crypto.CryptoException var9) {
            throw new CryptoException(var9.getMessage());
        }
    }

    @Override
    public boolean verify(byte[] pemCertificate, String signatureAlgorithm, byte[] signature, byte[] plainText) {
        boolean isVerified = false;
        X509Certificate certificate = this.getX509Certificate(pemCertificate);
        if (certificate != null) {
            isVerified = verify(certificate.getPublicKey(), null, plainText, signature);
        }
        return isVerified;
    }

    public boolean verify(PublicKey pubKey, byte[] withId, byte[] srcData, byte[] sign) {
        ECPublicKeyParameters pubkey = this.getPublicKey(pubKey);
        boolean isVerified = this.verify(pubkey, withId, srcData, sign);
        return isVerified;
    }

    public boolean verify(ECPublicKeyParameters pubKey, byte[] withId, byte[] srcData, byte[] sign) {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        if (withId != null) {
            param = new ParametersWithID(pubKey, withId);
        } else {
            param = pubKey;
        }

        signer.init(false, param);
        //配置fabric中验签，fabric源码中identity模块Verify方法将msg摘要后再验签
        srcData = hash(srcData);
        signer.update(srcData, 0, srcData.length);
        return signer.verifySignature(sign);
    }

    private X509Certificate getX509Certificate(byte[] pemCertificate) {
        ByteArrayInputStream bais = new ByteArrayInputStream(pemCertificate);
        X509Certificate cert = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            cert = (X509Certificate) cf.generateCertificate(bais);
        } catch (CertificateException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return cert;
    }

    @Override
    public byte[] hash(byte[] plainText) {
        SM3Digest digest = new SM3Digest();
        digest.update(plainText, 0, plainText.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    @Override
    public void loadCACertificates(Collection<Certificate> certificates) throws CryptoException {
        if (certificates != null && certificates.size() != 0) {
            try {
                Iterator var2 = certificates.iterator();

                while (var2.hasNext()) {
                    Certificate cert = (Certificate) var2.next();
                    this.addCACertificateToTrustStore(cert);
                }

            } catch (InvalidArgumentException var4) {
                throw new CryptoException("Unable to add certificate to trust store. Error: " + var4.getMessage(),
                        var4);
            }
        } else {
            throw new CryptoException("Unable to load CA certificates. List is empty");
        }
    }

    private void addCACertificateToTrustStore(Certificate certificate)
            throws InvalidArgumentException, CryptoException {
        String alias;
        if (certificate instanceof X509Certificate) {
            alias = ((X509Certificate) certificate).getSerialNumber().toString();
        } else {
            alias = Integer.toString(certificate.hashCode());
        }

        this.addCACertificateToTrustStore(certificate, alias);
    }

    private void addCACertificateToTrustStore(Certificate caCert, String alias)
            throws InvalidArgumentException, CryptoException {
        if (alias != null && !alias.isEmpty()) {
            if (caCert == null) {
                throw new InvalidArgumentException("Certificate cannot be null.");
            } else {
                try {
                    if (config.extraLogLevel(10) && null != diagnosticFileDumper) {
                        logger.trace("Adding cert to trust store. certificate");
                    }

                    this.getTrustStore().setCertificateEntry(alias, caCert);
                } catch (KeyStoreException var5) {
                    String emsg = "Unable to add CA certificate to trust store. Error: " + var5.getMessage();
                    logger.error(emsg, var5);
                    throw new CryptoException(emsg, var5);
                }
            }
        } else {
            throw new InvalidArgumentException(
                    "You must assign an alias to a certificate when adding to the trust store.");
        }
    }

    public KeyStore getTrustStore() throws CryptoException {
        if (this.trustStore == null) {
            this.createTrustStore();
        }

        return this.trustStore;
    }

    private void createTrustStore() throws CryptoException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load((InputStream) null, (char[]) null);
            this.setTrustStore(keyStore);
        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidArgumentException | KeyStoreException var2) {
            throw new CryptoException("Cannot create trust store. Error: " + var2.getMessage(), var2);
        }
    }

    private void setTrustStore(KeyStore keyStore) throws InvalidArgumentException {
        if (keyStore == null) {
            throw new InvalidArgumentException("Need to specify a java.security.KeyStore input parameter");
        } else {
            this.trustStore = keyStore;
        }
    }

    public boolean validateCertificate(Certificate cert) {
        if (cert == null) {
            return false;
        } else {
            boolean isValidated;
            try {
                KeyStore keyStore = this.getTrustStore();
                PKIXParameters parms = new PKIXParameters(keyStore);
                parms.setRevocationEnabled(false);
                CertPathValidator certValidator = CertPathValidator
                        .getInstance(CertPathValidator.getDefaultType(), BouncyCastleProvider.PROVIDER_NAME);
                ArrayList<Certificate> start = new ArrayList();
                start.add(cert);
                CertificateFactory certFactory = CertificateFactory.getInstance(this.CERTIFICATE_FORMAT, BouncyCastleProvider.PROVIDER_NAME);
                CertPath certPath = certFactory.generateCertPath(start);
                certValidator.validate(certPath, parms);
                isValidated = true;
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | CertificateException | CertPathValidatorException | CryptoException | NoSuchProviderException | KeyStoreException var9) {
                logger.error("Cannot validate certificate. Error is: " + var9.getMessage() + "\r\nCertificate" + cert
                        .toString());
                isValidated = false;
            }

            return isValidated;
        }
    }

    public void addCACertificatesToTrustStore(BufferedInputStream bis)
            throws CryptoException, InvalidArgumentException {
        if (bis == null) {
            throw new InvalidArgumentException("The certificate stream bis cannot be null");
        } else {
            try {
                Collection<? extends Certificate> certificates = this.cf.generateCertificates(bis);
                Iterator var3 = certificates.iterator();

                while (var3.hasNext()) {
                    Certificate certificate = (Certificate) var3.next();
                    this.addCACertificateToTrustStore(certificate);
                }

            } catch (CertificateException var5) {
                throw new CryptoException("Unable to add CA certificate to trust store. Error: " + var5.getMessage(),
                        var5);
            }
        }
    }

    boolean validateCertificate(byte[] certPEM) {
        if (certPEM == null) {
            return false;
        } else {
            try {
                X509Certificate certificate = this.getX509Certificate(certPEM);
                if (null == certificate) {
                    throw new Exception("Certificate transformation returned null");
                } else {
                    return this.validateCertificate(certificate);
                }
            } catch (Exception e) {
                logger.error("Cannot validate certificate. Error is: "
                        + e.getMessage() + "\r\nCertificate (PEM, hex): "
                        + DatatypeConverter.printHexBinary(certPEM));
                return false;
            }
        }
    }

    @Override
    public void loadCACertificatesAsBytes(Collection<byte[]> certificatesBytes) throws CryptoException {
        if (certificatesBytes != null && certificatesBytes.size() != 0) {
            StringBuilder sb = new StringBuilder(1000);
            ArrayList<Certificate> certList = new ArrayList();

            byte[] certBytes;
            for (Iterator var4 = certificatesBytes.iterator(); var4.hasNext();
                 certList.add(this.bytesToCertificate(certBytes))) {
                certBytes = (byte[]) var4.next();
                if (null != diagnosticFileDumper) {
                    sb.append("certificate to load:\n").append(new String(certBytes, StandardCharsets.UTF_8));
                }
            }

            this.loadCACertificates(certList);
            if (diagnosticFileDumper != null && sb.length() > 1) {
                logger.trace("loaded certificates");
            }
        } else {
            throw new CryptoException("List of CA certificates is empty. Nothing to load.");
        }
    }

    @Override
    public String generateCertificationRequest(String subject, KeyPair keypair)
            throws InvalidArgumentException {

        SM2PublicKey sm2PublicKey = new SM2PublicKey(keypair.getPublic().getAlgorithm(),
                (BCECPublicKey) keypair.getPublic());

        try {
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal("CN=" + subject), sm2PublicKey);

            ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keypair.getPrivate());

            return this.certificationRequestToPEM(p10Builder.build(signer));
        } catch (Exception e) {

            logger.error(e);
            throw new InvalidArgumentException(e);

        }
    }

    private String certificationRequestToPEM(PKCS10CertificationRequest csr) throws IOException {
        PemObject pemCSR = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(str);
        pemWriter.writeObject(pemCSR);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    /**
     * Return PrivateKey  from pem bytes.
     *
     * @param pemKey pem-encoded private key
     */
    @Override
    public PrivateKey bytesToPrivateKey(byte[] pemKey) throws CryptoException {
        PrivateKey pk;
        try {
            PemReader pr = new PemReader(new StringReader(new String(pemKey)));
            PemObject po = pr.readPemObject();
            PEMParser pem = new PEMParser(new StringReader(new String(pemKey)));

            if (po.getType().equals("PRIVATE KEY")) {
                pk = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) pem.readObject());
            } else {
                logger.trace("Found private key with type " + po.getType());
                PEMKeyPair kp = (PEMKeyPair) pem.readObject();
                pk = new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
            }
        } catch (Exception e) {
            throw new CryptoException("Failed to convert private key bytes", e);
        }
        return pk;
    }

    @Override
    public Certificate bytesToCertificate(byte[] certBytes) throws CryptoException {
        if (certBytes != null && certBytes.length != 0) {
            return this.getX509Certificate(certBytes);
        } else {
            throw new CryptoException("bytesToCertificate: input null or zero length");
        }
    }

    public byte[] certificateToDER(String certificatePEM) {

        byte[] content = null;

        try (PemReader pemReader = new PemReader(new StringReader(certificatePEM))) {
            final PemObject pemObject = pemReader.readPemObject();
            content = pemObject.getContent();

        } catch (IOException e) {
            // best attempt
        }

        return content;
    }

    private static String checkSecurityProviderClassName(String className) {
        String str;
        if (className.equals(SecurityProviderClassName)) {
            str = SecurityProviderClassName;
            return str;
        } else {
            throw new RuntimeException("Invalid SecurityProviderClassName");
        }
    }
}
