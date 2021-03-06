/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package df.sign.server;

import df.sign.SignEngine;
import df.sign.SignUtils;
import df.sign.pkcs11.CertificateData;
import df.sign.utils.X509Utils;
import java.util.Locale;

/**
 *
 * @author akaplan
 */
public class pdfSign {

    public SignEngine signEngine = null;

    public boolean readAllCertificates = false;
    public String dnRestrictedSignatureName = "";

    public pdfSign(SignEngine signEngine) {
        this.signEngine = signEngine;
    }

    public String sign(String certID, String pin) throws Exception {

        String certValid = isCertificateCorrect(certID);

        if (!certValid.isEmpty()) {
            throw new Exception(certValid);
        }

        CertificateData certData = SignUtils.getCertificateDataByID(certID, signEngine.certificateList);

        if (certData == null) {
            if (signEngine.getNumDataToSign() == 0) {
                // JOptionPane.showMessageDialog(null, "NO DATA TO SIGN", "ERROR", JOptionPane.ERROR_MESSAGE);
                throw new Exception("ERROR : NO DATA TO SIGN");
            }

            try {
                signEngine.sign(certData, pin);
                return "";
            } catch (Exception e) {
                e.printStackTrace();
                throw new Exception("ERROR DURING THE SIGNING PROCESS:\n" + e.getMessage());
            }
        }

        return "";
    }

    private String isCertificateCorrect(String certID) {
        CertificateData certData = SignUtils.getCertificateDataByID(certID, signEngine.certificateList);

        if (certData == null) {
            // SignUtils.playBeeps(2);
            // JOptionPane.showMessageDialog(null, "CERTIFICATE NOT SELECTED", "ERRORE", JOptionPane.ERROR_MESSAGE);
            return "ERROR : CERTIFICATE NOT SELECTED";
        }

        if (dnRestrictedSignatureName.length() != 0) {
            String cfCert = X509Utils.getCFFromCertSubject(certData.cert.asX509Certificate().getSubjectDN().getName());
            if (!cfCert.equals(dnRestrictedSignatureName.toUpperCase(new Locale("tr", "TR")))) {
                if (!certData.cert.asX509Certificate().getSubjectDN().getName().contains(dnRestrictedSignatureName.toUpperCase(new Locale("tr", "TR")))) {
                    return "ERROR : SIGNATURE AVAILABLE ONLY FOR USER " + dnRestrictedSignatureName + "\nThe selected certificate is valid for user " + cfCert;

                }
            }
        }

        if (!X509Utils.checkValidity(certData.cert.asX509Certificate(), null)) {
            //int ret = JOptionPane.showConfirmDialog(null, "THE CERTIFICATE IS EXPIRED\nPROCEEDS ANYWAY?", "WARNING", JOptionPane.YES_NO_OPTION);
            //if(ret != JOptionPane.YES_OPTION)
            return "ERROR : THE CERTIFICATE IS EXPIRED";
        }

        if (X509Utils.checkIsSelfSigned(certData.cert.asX509Certificate())) {
            //int ret = JOptionPane.showConfirmDialog(null, "THE CERTIFICATE IS SELF SIGNED\nPROCEEDS ANYWAY?", "WARNING", JOptionPane.YES_NO_OPTION);
            //if(ret != JOptionPane.YES_OPTION)
            return "ERROR : THE CERTIFICATE IS SELF SIGNED";
        }

        if (X509Utils.checkIsRevoked(certData.cert.asX509Certificate())) {
            //int ret = JOptionPane.showConfirmDialog(null, "THE CERTIFICATE IS REVOKED\nPROCEEDS ANYWAY?", "WARNING", JOptionPane.YES_NO_OPTION);
            //if(ret != JOptionPane.YES_OPTION){
            return "ERROR : THE CERTIFICATE IS REVOKED";
        }

        return "";
    }
}
