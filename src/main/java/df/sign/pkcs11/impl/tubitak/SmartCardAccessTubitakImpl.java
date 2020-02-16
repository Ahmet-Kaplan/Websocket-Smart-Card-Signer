/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package df.sign.pkcs11.impl.tubitak;

/**
 *
 * @author akaplan
 */
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.PolicyReader;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.ValidationPolicy;
import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.EParameters;
import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.BaseSignedData;
import tr.gov.tubitak.uekae.esya.api.cmssignature.validation.SignedDataValidation;
import tr.gov.tubitak.uekae.esya.api.cmssignature.validation.SignedDataValidationResult;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.common.crypto.Algorithms;
import tr.gov.tubitak.uekae.esya.api.common.crypto.BaseSigner;
import tr.gov.tubitak.uekae.esya.api.common.util.LicenseUtil;
import tr.gov.tubitak.uekae.esya.api.common.util.bag.Pair;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.SignatureAlg;
import tr.gov.tubitak.uekae.esya.api.crypto.exceptions.CryptoException;
import tr.gov.tubitak.uekae.esya.api.crypto.util.PfxParser;
import tr.gov.tubitak.uekae.esya.api.pades.PAdESContext;
import tr.gov.tubitak.uekae.esya.api.signature.ContainerValidationResult;
import tr.gov.tubitak.uekae.esya.api.signature.Context;
import tr.gov.tubitak.uekae.esya.api.signature.Signature;
import tr.gov.tubitak.uekae.esya.api.signature.SignatureContainer;
import tr.gov.tubitak.uekae.esya.api.signature.SignatureException;
import tr.gov.tubitak.uekae.esya.api.signature.SignatureFactory;
import tr.gov.tubitak.uekae.esya.api.signature.SignatureFormat;
import tr.gov.tubitak.uekae.esya.api.signature.SignatureType;
import tr.gov.tubitak.uekae.esya.api.signature.config.Config;
import tr.gov.tubitak.uekae.esya.api.signature.impl.BaseSignable;
import tr.gov.tubitak.uekae.esya.api.signature.impl.SignableBytes;
import tr.gov.tubitak.uekae.esya.api.signature.util.PfxSigner;
import tr.gov.tubitak.uekae.esya.api.smartcard.apdu.APDUSmartCard;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.BaseSmartCard;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.CardType;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.LoginException;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.P11SmartCard;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.SmartCardException;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.SmartOp;

import java.util.ArrayList;

import df.sign.pkcs11.CertificateData;
import df.sign.pkcs11.SmartCardAccessI;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

public class SmartCardAccessTubitakImpl implements SmartCardAccessI {

    private BaseSmartCard smartCard = null;
    private String[] Terminals = null;

    public String configFile;
    public String dataTextFile;
    public String dataFileContentType;
    public String policyFile;
    public String licenseFile;

    public SmartCardAccessTubitakImpl() {
        this.policyFile = "certval-policy-test.xml";
        this.dataFileContentType = "text/plain";
        this.dataTextFile = "data.txt";
        this.configFile = "esya-signature-config.xml";
        this.licenseFile = "lisans.xml";
        try {
            setLicenseXml();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private ValidationPolicy getPolicy() throws ESYAException {
        try {
            return PolicyReader.readValidationPolicy(new FileInputStream(policyFile));
        } catch (FileNotFoundException ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private Context createContext(byte[] tobeSignBytes) {
        Context c = new Context();
        c.setConfig(new Config(configFile));
        c.setData(new SignableBytes(tobeSignBytes, dataTextFile, dataFileContentType));
        return c;
    }

    private PAdESContext createPadesContext(String fileName) {
        PAdESContext c = new PAdESContext(new File(fileName).toURI());
        c.setConfig(new Config(configFile));
        return c;
    }

    private ECertificate getPfxCertificate(InputStream pfxFileInputstream, String pinCode) throws CryptoException {
        PfxParser p = new PfxParser(pfxFileInputstream, pinCode.toCharArray());
        List<Pair<ECertificate, PrivateKey>> ls = p.getCertificatesAndKeys();
        return (ECertificate) ((Pair) ls.get(0)).getObject1();
    }

    private BaseSignable createContent(byte[] tobeSignBytes) {
        return new SignableBytes(tobeSignBytes, dataTextFile, dataFileContentType);
    }

    public ArrayList<CertificateData> getCertificateList(long slotID) throws SmartCardException, ESYAException, PKCS11Exception, IOException {
        ArrayList<CertificateData> result = new ArrayList<CertificateData>();

        Terminals = SmartOp.getCardTerminals();

        for (String terminal : Terminals) {
            if (terminal != null && !terminal.isEmpty()) {
                if (smartCard == null) {
                    smartCard = getSmartCard(terminal);
                }
                if (smartCard != null) {
                    if (APDUSmartCard.isSupported(terminal)) {

                        CardTerminal ct = TerminalFactory.getDefault().terminals().getTerminal(terminal);
                        ((APDUSmartCard) smartCard).openSession(ct);

                    } else {
                        Pair<Long, CardType> slotAndCardType = SmartOp.getSlotAndCardType(terminal);
                        smartCard.openSession((slotAndCardType.getObject1()));
                    }
                    if (smartCard.isSessionActive()) {
                        List<byte[]> certificatesBytes = smartCard.getSignatureCertificates();
                        if (certificatesBytes != null) {
                            for (byte[] bs : certificatesBytes) {
                                ECertificate cert = new ECertificate(bs);
                                CertificateData certData = new CertificateData();

                                certData.cert = cert.asX509Certificate();
                                certData.certID = cert.getEncoded();
                                certData.certLABEL = cert.getEmail().getBytes();
                                certData.id = cert.getEmail();
                                certData.slot = slotID;

                                result.add(certData);
                            }
                        }
                        smartCard.closeSession();
                    }
                }
            }
        }
        return result;
    }

    private byte[] signWithSmartCard(String terminal, ECertificate signatureCertificate, String pinCode, byte[] tobeSignBytes) throws SmartCardException, LoginException, SignatureException, PKCS11Exception, IOException, ESYAException {
        byte[] result = null;
        if (terminal != null && !terminal.isEmpty() && signatureCertificate != null && pinCode != null && !pinCode.isEmpty() && tobeSignBytes != null) {
            if (smartCard == null) {
                smartCard = getSmartCard(terminal);
            }
            if (smartCard != null) {
                if (APDUSmartCard.isSupported(terminal)) {
                    CardTerminal ct = TerminalFactory.getDefault().terminals().getTerminal(terminal);
                    ((APDUSmartCard) smartCard).openSession(ct);
                } else {
                    Pair<Long, CardType> slotAndCardType = SmartOp.getSlotAndCardType(terminal);
                    smartCard.openSession((slotAndCardType.getObject1()));
                }

                if (smartCard.isSessionActive()) {

                    BaseSigner signer = smartCard.getSigner(signatureCertificate.asX509Certificate(), Algorithms.SIGNATURE_RSA_SHA256);
                    smartCard.login(pinCode);
                    SignatureContainer container = SignatureFactory.createContainer(SignatureFormat.CAdES, createContext(tobeSignBytes));
                    Signature signature = container.createSignature(signatureCertificate);
                    signature.addContent(createContent(tobeSignBytes), true);
                    signature.sign(signer);

                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    container.write(out);
                    result = out.toByteArray();

                    smartCard.logout();
                    smartCard.closeSession();

                }
            }
        }
        return result;
    }

    private byte[] signWithPfxFile(String pfxFile, String pinCode, byte[] tobeSignBytes) throws CryptoException, SignatureException, FileNotFoundException {
        byte[] result;
        ECertificate certificate = getPfxCertificate(new FileInputStream(pfxFile), pinCode);
        PfxSigner signer = new PfxSigner(SignatureAlg.RSA_SHA256, new FileInputStream(pfxFile), pinCode.toCharArray());
        SignatureContainer container = SignatureFactory.createContainer(SignatureFormat.CAdES, createContext(tobeSignBytes));
        Signature signature = container.createSignature(certificate);
        signature.addContent(createContent(tobeSignBytes), true);
        signature.sign(signer);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        container.write(out);
        result = out.toByteArray();
        return result;
    }

    private SignedDataValidationResult validateSign(String signedFile) throws IOException, SignatureException, ESYAException {

        FileInputStream fileInputStream = new FileInputStream(signedFile);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = fileInputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }

        //BaseSignedData baseSignedData = new BaseSignedData(baos.toByteArray());
        Map<String, Object> params = new HashMap();
        params.put(EParameters.P_CERT_VALIDATION_POLICY, getPolicy());
        //Use only reference and their corresponding value to validate signature
        params.put(EParameters.P_FORCE_STRICT_REFERENCE_USE, true);

        //Ignore grace period which means allow usage of CRL published before signature time 
        //params.put(EParameters.P_IGNORE_GRACE, true);
        //Use multiple policies if you want to use different policies to validate different types of certificate
        //CertValidationPolicies certificateValidationPolicies = new CertValidationPolicies();
        //certificateValidationPolicies.register(CertificateType.DEFAULT.toString(), policy);
        //ValidationPolicy maliMuhurPolicy=PolicyReader.readValidationPolicy(new FileInputStream("./config/certval-policy-malimuhur.xml"));
        //certificateValidationPolicies.register(CertificateType.MaliMuhurCertificate.toString(), maliMuhurPolicy);
        //params.put(EParameters.P_CERT_VALIDATION_POLICIES, certificateValidationPolicies);
//            if (externalContent != null) {
//                params.put(EParameters.P_EXTERNAL_CONTENT, externalContent);
//            }
        SignedDataValidation sdv = new SignedDataValidation();
        SignedDataValidationResult sdvr = sdv.verify(baos.toByteArray(), params);

        return sdvr;

    }

    private void extractSignedFile(String signedFile, OutputStream output) throws SignatureException, IOException {

        FileInputStream fileInputStream = new FileInputStream(signedFile);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = fileInputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }
        BaseSignedData baseSignedData = new BaseSignedData(baos.toByteArray());
//            baseSignedData.getAllSigners().forEach(new Consumer<Signer>() {
//                @Override
//                public void accept(Signer t) {
//                    System.out.println(t.getSignerCertificate().getIssuer().getCommonNameAttribute());
//                }
//            });
        output.write(baseSignedData.getContent());
        output.close();

    }

    private BaseSmartCard getSmartCard(String terminal) throws PKCS11Exception, IOException, ESYAException {
        boolean APDUSupport;
        try {
            APDUSupport = APDUSmartCard.isSupported(terminal);
        } catch (NoClassDefFoundError ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, null, "AkisCIF.jar is missing");
            APDUSupport = false;
        }
        P11SmartCard p11SmartCard;
        if (APDUSupport) {
            APDUSmartCard asc = new APDUSmartCard();
            return asc;

        } else {
            Pair<Long, CardType> slotAndCardType;
            slotAndCardType = SmartOp.getSlotAndCardType(terminal);
            if ((terminal.contains("ACS")) && (((CardType) slotAndCardType.getObject2()).toString().compareTo(CardType.UNKNOWN.toString()) == 0)) {
                if (terminal.contains("ACR38U")) {
                    long slotNum = SmartOp.findSlotNumber(CardType.TKART);
                    slotAndCardType.setObject1(slotNum);
                    slotAndCardType.setObject2(CardType.TKART);
                } else {
                    long slotNum = SmartOp.findSlotNumber(CardType.SAFESIGN);
                    slotAndCardType.setObject1(slotNum);
                    slotAndCardType.setObject2(CardType.SAFESIGN);
                }
            } else if ((terminal.contains("OMNIKEY CardMan 3x21")) && (((CardType) slotAndCardType.getObject2()).toString().compareTo(CardType.UNKNOWN.toString()) == 0)) {
                long slotNum = SmartOp.findSlotNumber(CardType.TKART);
                slotAndCardType.setObject1(slotNum);
                slotAndCardType.setObject2(CardType.TKART);
            } else if ((terminal.contains("OMNIKEY")) && (((CardType) slotAndCardType.getObject2()).toString().compareTo(CardType.UNKNOWN.toString()) == 0)) {
                long slotNum = SmartOp.findSlotNumber(CardType.TKART);
                slotAndCardType.setObject1(slotNum);
                slotAndCardType.setObject2(CardType.TKART);
            } else if ((terminal.contains("Gemplus")) && (((CardType) slotAndCardType.getObject2()).toString().compareTo(CardType.UNKNOWN.toString()) == 0)) {
                long slotNum = SmartOp.findSlotNumber(CardType.TKART);
                slotAndCardType.setObject1(slotNum);
                slotAndCardType.setObject2(CardType.TKART);
            }
            p11SmartCard = new P11SmartCard((CardType) slotAndCardType.getObject2());
            return p11SmartCard;
        }
    }

    private Boolean setLicenseXml() throws Exception, ESYAException, FileNotFoundException {

        InputStream licenseStream = this.getClass().getResourceAsStream(licenseFile);

        boolean ret = LicenseUtil.setLicenseXml(licenseStream);
        Date expirationDate = LicenseUtil.getExpirationDate();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        System.out.println("License Expiration Date :" + dateFormat.format(expirationDate));
        return ret;

    }

    private Boolean setLicenseXmlWithPassword(String password) throws ESYAException, FileNotFoundException {
        InputStream licenseStream = this.getClass().getResourceAsStream(licenseFile);
        return LicenseUtil.setLicenseXml(licenseStream, password);
    }

    private byte[] signPdfWithSmartCard(String terminal, ECertificate signatureCertificate, String pinCode, String pdfFile) throws SmartCardException, LoginException, SignatureException, FileNotFoundException, PKCS11Exception, IOException, ESYAException {
        byte[] result = null;
        if (terminal != null && !terminal.isEmpty() && signatureCertificate != null && pinCode != null && !pinCode.isEmpty() && pdfFile != null) {
            smartCard = getSmartCard(terminal);

            if (smartCard != null) {
                if (APDUSmartCard.isSupported(terminal)) {
                    CardTerminal ct = TerminalFactory.getDefault().terminals().getTerminal(terminal);
                    ((APDUSmartCard) smartCard).openSession(ct);
                } else {
                    Pair<Long, CardType> slotAndCardType = SmartOp.getSlotAndCardType(terminal);
                    smartCard.openSession((slotAndCardType.getObject1()));
                }

                if (smartCard.isSessionActive()) {

                    BaseSigner signer = smartCard.getSigner(signatureCertificate.asX509Certificate(), Algorithms.SIGNATURE_RSA_SHA256);
                    smartCard.login(pinCode);
                    SignatureContainer container = SignatureFactory.readContainer(SignatureFormat.PAdES, new FileInputStream(pdfFile), createPadesContext(pdfFile));
                    Signature signature = container.createSignature(signatureCertificate);
                    signature.setSigningTime(Calendar.getInstance());
                    signature.sign(signer);

                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    container.write(out);
                    result = out.toByteArray();

                    smartCard.logout();
                    smartCard.closeSession();

                }
            }
        }
        return result;
    }

    private byte[] signPdfWithPfxFile(String pfxFile, String pinCode, String pdfFile) throws CryptoException, SignatureException, FileNotFoundException {
        byte[] result;

        ECertificate certificate = getPfxCertificate(new FileInputStream(pfxFile), pinCode);
        PfxSigner signer = new PfxSigner(SignatureAlg.RSA_SHA256, new FileInputStream(pfxFile), pinCode.toCharArray());
        SignatureContainer container = SignatureFactory.readContainer(SignatureFormat.PAdES, new FileInputStream(pdfFile), createPadesContext(pdfFile));
        Signature signature = container.createSignature(certificate);
        signature.setSigningTime(Calendar.getInstance());
        signature.sign(signer);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        container.write(out);
        result = out.toByteArray();

        return result;

    }

    private ContainerValidationResult validateSignedPdf(String signedFile) throws FileNotFoundException, SignatureException {
        SignatureContainer sc = SignatureFactory.readContainer(new FileInputStream(signedFile), createPadesContext(signedFile));
        return sc.verifyAll();
    }

    private byte[] convertSignedPdfToTimeStampedPdf(String pdfFile) throws CryptoException, SignatureException, FileNotFoundException, IOException, ESYAException {
        FileInputStream fileInputStream = new FileInputStream(pdfFile);
        PAdESContext context = new PAdESContext();
        context.setConfig(new Config(configFile));
        context.setSignWithTimestamp(true);

        SignatureContainer pc = SignatureFactory.readContainer(
                SignatureFormat.PAdES,
                fileInputStream, context);

        int count = pc.getSignatures().size();

        for (int i = 0; i < count; i++) {
            Signature signature = pc.getSignatures().get(i);
            signature.upgrade(SignatureType.ES_XL);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        pc.write(baos);
        return baos.toByteArray();
    }

    @Override
    public long[] connectToLibrary(String library) throws Exception, Error {
        System.out.println("Connection to " + library);

        long[] ret = new long[0];

        return ret;
    }

    @Override
    public long getPinMinLength(long slotID) throws Exception, Error {
        return 4;// getSlot(slotID).getToken().getTokenInfo().getMinPinLen();
    }

    @Override
    public long getPinMaxLength(long slotID) throws Exception, Error {
        return 16; //getSlot(slotID).getToken().getTokenInfo().getMaxPinLen();
    }

    @Override
    public long login(long slotID, String pin) throws Exception, Error {

        byte[] result = null;

        String terminal = Terminals[(int) slotID];

        if (terminal != null && !terminal.isEmpty() && pin != null && !pin.isEmpty()) {
            if (smartCard == null) {
                smartCard = getSmartCard(terminal);
            }
            if (smartCard != null) {
                if (APDUSmartCard.isSupported(terminal)) {
                    CardTerminal ct = TerminalFactory.getDefault().terminals().getTerminal(terminal);
                    ((APDUSmartCard) smartCard).openSession(ct);
                } else {
                    Pair<Long, CardType> slotAndCardType = SmartOp.getSlotAndCardType(terminal);
                    smartCard.openSession((slotAndCardType.getObject1()));
                }

                if (smartCard.isSessionActive()) {
                    smartCard.login(pin);
                }
            }
        }

        return 0L;
    }

    @Override
    public byte[] signData(long sessionID, byte[] certId, byte[] certLabel, byte[] data) throws Exception, Error {
        if (smartCard == null) {
            throw new Exception("session not initialized");
        }

        byte[] signature = null;// smartCard.getSigner(data);
        return signature;
    }

    @Override
    public void closeSession(long sessionID) {
        try {
            if (smartCard != null) {
                smartCard.logout();
            }
        } catch (Exception | Error e) {
        }

        try {
            if (smartCard != null) {
                smartCard.closeSession();
            }
        } catch (Exception | Error e) {
        }

        smartCard = null;
    }

    @Override
    public void disconnectLibrary() {
        try {

        } catch (Exception | Error e) {
        }

        smartCard = null;
    }

    /*
    public static void main(String[] args) {
        try{
            SmartCardAccessIaikImpl cardManager = new SmartCardAccessIaikImpl();
            long[] slotList = cardManager.connectToLibrary("C:\\WINDOWS\\System32\\bit4ipki.dll");
            ArrayList<CertificateData> certificateDataList = cardManager.getCertificateList(slotList[0]);
            long sessionHandle = cardManager.login(slotList[0], "");
            CertificateData certificateData = certificateDataList.get(0);
            System.out.println(certificateData.cert.getSubjectDN().getName());
            
            byte[] dataTest = "test".getBytes();
            byte[] hashToSign = SignUtils.calculateHASH(org.bouncycastle.cms.CMSSignedDataGenerator.DIGEST_SHA256, dataTest);
            hashToSign = df.sign.cms.CMSSignedDataWrapper.getDigestInfoToSign(org.bouncycastle.cms.CMSSignedDataGenerator.DIGEST_SHA256, hashToSign);
            
            byte[] signed = cardManager.signData(sessionHandle, certificateData.certID, certificateData.certLABEL, hashToSign);
            cardManager.closeSession(sessionHandle);
            cardManager.disconnectLibrary();
            
            java.security.Signature sig = java.security.Signature.getInstance("SHA256WithRSA", "BC");
            sig.initVerify(certificateData.cert.getPublicKey());
            sig.update(dataTest);
            System.out.println("Signature verified: " + sig.verify(signed));
            
        }catch(Exception e){e.printStackTrace();}catch(Error e){e.printStackTrace();}
    }
     */
}
