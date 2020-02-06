/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package df.sign;

import df.sign.pkcs11.CertificateData;
import df.sign.utils.IOUtils;
import java.util.ArrayList;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

/**
 *
 * @author akaplan
 */
@ServerEndpoint(value = "/showhelp")
public class showHelp {

    private Session session = null;

    public void sendTestData() {
        session.getAsyncRemote().sendText("{\"HelpList\" : []}");
    }

    @OnOpen
    public void open(Session session) {
        this.session = session;
    }

    @OnClose
    public void onClose(Session session) {
    }

    @OnError
    public void onError(Throwable exception, Session session) {
    }

    public SignEngine signEngine = null;

    public boolean readAllCertificates = false;

    public showHelp(SignEngine signEngine) {
        this.signEngine = signEngine;
    }

    @OnMessage
    public String showHelp(String message, Session session) {
        try {

            ArrayList<CertificateData> certList = new ArrayList<CertificateData>();
            try {
                certList = signEngine.loadSmartCardCertificateList(readAllCertificates).certificateList;
            } catch (Exception e) {
                e.printStackTrace();
                SignUtils.playBeeps(1);
            }

            JsonArrayBuilder helpList = Json.createArrayBuilder();

            String[] dllList = signEngine.dllList;

            String conflicts = "No JAR conflicts identified";
            String[] conflictJARList = SignUtils.checkJarConflicts();
            if (conflictJARList.length != 0) {
                conflicts = "";
                for (String conflictJAR : conflictJARList) {
                    conflicts += "- " + conflictJAR + "\n";
                }
            }
            helpList.add("Conflicts: " + conflicts);
            helpList.add("---");

            helpList.add("LIBRARY NAME \t STATUS \t SMARTCARD TYPE");

            String tableList = "";
            for (int i = 0; i < dllList.length; i++) {
                tableList = "";
                tableList += dllList[i] + "\t";
                tableList += (SignUtils.getLibraryFullPath(dllList[i]) != null) ? "INSTALLED" : "NOT INSTALLED" + "\t";
                tableList += (SignUtils.getCardTypeFromDLL(dllList[i]) != "") ? SignUtils.getCardTypeFromDLL(dllList[i]) : "NOT MANAGED" + "\t";
                helpList.add(tableList);
            }
            helpList.add("---");

            helpList.add("CONNECTED SMARTCARD INFOS:");

            String smartcardInfo = "";
            ArrayList<String> cardATRList = SignUtils.getConnectedCardATR();
            if (cardATRList.size() == 0) {
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
                            if (dllFullPath != "") {
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

            helpList.add(smartcardInfo);
            helpList.add("---");
            helpList.add("LOGS");
            try {
                helpList.add(new String(IOUtils.readFile(SignUtils.logFilePath)));
            } catch (Exception e) {
            }

            JsonObject ret = Json.createObjectBuilder().add("HelpList", helpList).build();
            String retS = ret.toString();

            return retS;

        } catch (Exception ex) {
            ex.printStackTrace();
            return "{\"error\" : \"" + ex.getMessage().replace("\"", "\\\"").replace("\\", "\\\\") + "\"}";
        } finally {
            //SignFactory.getUniqueWebSocketServer().terminate();
        }
    }

}
