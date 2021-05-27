package org.hyperledger.client;

import org.apache.commons.io.FileUtils;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import java.io.File;
import java.security.PrivateKey;
import java.util.Set;

public class FabricUser implements User {

    private String name;
    private String mspId;
    private String signAlg;
    private Enrollment enrollment;

    public FabricUser(String name, String mspId, String signAlg,byte[] keyFile, byte[] certFile) throws Exception {
        this.name = name;
        this.mspId = mspId;
        this.signAlg = signAlg;
        enrollment = this.loadFromPemfile(keyFile, certFile,signAlg);
    }

    public FabricUser(Enrollment enrollment){
        this.enrollment = enrollment;
    }


    public static Enrollment loadFromPemfile(byte[] keyFile, byte[] certFile, String signAlg) throws Exception {
        CryptoSuite suite = getCryptoSuite(signAlg);
        PrivateKey privatekey = suite.bytesToPrivateKey(keyFile);
        return new X509Enrollment(privatekey, new String(certFile));
    }

    public static Enrollment loadFromPemfile(File keyFile, File certFile, String caType) throws Exception {
        byte[] key = FileUtils.readFileToByteArray(keyFile);
        byte[] cert = FileUtils.readFileToByteArray(certFile);
        CryptoSuite suite = getCryptoSuite(caType);
        PrivateKey privatekey = suite.bytesToPrivateKey(key);
        return new X509Enrollment(privatekey, new String(cert));
    }

    public static CryptoSuite getCryptoSuite(String signAlg) throws Exception {
        CryptoSuite suite;
        if (Constant.GMCA.equals(signAlg) || Constant.SM2.equals(signAlg)) {
            suite = CryptoSuite.Factory.getCryptoSuite(Constant.SM3);
        } else {
            suite = CryptoSuite.Factory.getCryptoSuite();
        }
        return suite;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Set<String> getRoles() {
        return null;
    }

    @Override
    public String getAccount() {
        return null;
    }

    @Override
    public String getAffiliation() {
        return null;
    }

    @Override
    public Enrollment getEnrollment() {
        return enrollment;
    }

    @Override
    public String getMspId() {
        return mspId;
    }

    public String getSignAlg() {
        return signAlg;
    }
}
