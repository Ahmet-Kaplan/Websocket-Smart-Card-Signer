/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package df.sign.server;

import df.sign.SignEngine;
import df.sign.SignUtils;
import df.sign.pkcs11.CertificateData;
import df.sign.utils.IOUtils;
import java.util.ArrayList;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import spark.Request;
import spark.Response;

/**
 *
 * @author akaplan
 */
public class showInfo {

    public SignEngine signEngine = null;

    public boolean readAllCertificates = false;

    public showInfo(SignEngine signEngine) {
        this.signEngine = signEngine;
    }

    public String showHelp(Request request, Response response) {
        try {

            ArrayList<CertificateData> certList = new ArrayList<CertificateData>();
            try {
                certList = signEngine.loadSmartCardCertificateList(readAllCertificates).certificateList;
            } catch (Exception e) {
                e.printStackTrace();
            }

            JsonObjectBuilder infoList = Json.createObjectBuilder();

            String[] dllList = signEngine.dllList;

            String conflicts = "No JAR conflicts identified";
            String[] conflictJARList = SignUtils.checkJarConflicts();
            if (conflictJARList.length != 0) {
                conflicts = "";
                for (String conflictJAR : conflictJARList) {
                    conflicts += "- " + conflictJAR + "\n";
                }
            }
            infoList.add("Conflicts", conflicts);

            JsonObjectBuilder libraries ;

            for (int i = 0; i < dllList.length; i++) {
                if (SignUtils.getLibraryFullPath(dllList[i]) != null) {
                    libraries = Json.createObjectBuilder();
                    libraries.add("File name", dllList[i]);
                    libraries.add("Card Type",
                            ((SignUtils.getCardTypeFromDLL(dllList[i]) != "") ? SignUtils.getCardTypeFromDLL(dllList[i]) : "NOT MANAGED"));
                    infoList.add("Libraries", libraries);
                }
            }
           
            String smartcardInfo;

            ArrayList<String> cardATRList = SignUtils.getConnectedCardATR();
            if (cardATRList.isEmpty()) {
                smartcardInfo = "SMARTCARD NOT CONNECTED\n";
            } else {
                smartcardInfo = "CONNECTED SMARTCARDS:\n";
                for (String cardATR : cardATRList) {
                    String[] cardInfo = SignUtils.getCardInfo(cardATR);
                    if (cardInfo == null) {
                        smartcardInfo += "- UNKNOWN. ATR: " + cardATR + "\n";
                    } else {
                        smartcardInfo += "- " + cardInfo[0] + "\tPKCS11: ";
                        String[] cardInfoDllList = cardInfo[1].split("%");
                        String urlDllInstaller = cardInfo[3];
                        String correctLibrary = "";
                        for (String cardInfoDll : cardInfoDllList) {
                            String dllFullPath = SignUtils.getLibraryFullPath(cardInfoDll);
                            if (!dllFullPath.isEmpty()) {
                                correctLibrary = dllFullPath;
                                break;
                            }
                        }
                        if (correctLibrary == "") {
                            smartcardInfo += "NOT INSTALLED-> " + dllList[0] + " DOWNLOAD URL: " + urlDllInstaller + "\n";
                        } else {
                            smartcardInfo += "INSTALLED->" + correctLibrary + "\n";
                        }
                    }
                }
            }

            infoList.add("Smartcards", smartcardInfo);

            try {
                infoList.add("Logs", new String(IOUtils.readFile(SignUtils.logFilePath)));
            } catch (Exception e) {
            }

            JsonObject ret = Json.createObjectBuilder().add("HelpList", infoList).build();
            return ret.toString();

        } catch (Exception ex) {
            ex.printStackTrace();
            return "{\"error\" : \"" + ex.getMessage().replace("\"", "\\\"").replace("\\", "\\\\") + "\"}";
        } finally {
            //SignFactory.getUniqueWebSocketServer().terminate();
        }
    }

}
