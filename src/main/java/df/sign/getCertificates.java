/*
    Websocket Smartcard Signer
    Copyright (C) 2017  Damiano Falcioni (damiano.falcioni@gmail.com)
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. 
 */
package df.sign;

import java.util.ArrayList;
import df.sign.pkcs11.CertificateData;
import df.sign.utils.IOUtils;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint(value = "/certificates")
public class getCertificates {

    private Session session = null;

    public void sendTestData() {
        session.getAsyncRemote().sendText("{\"certificates\" : []}");
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

    public getCertificates(SignEngine signEngine) {
        this.signEngine = signEngine;
    }

    
    @OnMessage
    public String getCertificates(String message, Session session) {
        try {

            ArrayList<CertificateData> certList = new ArrayList<CertificateData>();
            try {
                certList = signEngine.loadSmartCardCertificateList(readAllCertificates).certificateList;
            } catch (Exception e) {
                e.printStackTrace();
                SignUtils.playBeeps(1);
            }

            JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
            for (CertificateData cert : certList) {
                String certLABEL = new String(SignUtils.base64Encode(cert.certLABEL), "UTF-8");
                jsonArrayBuilder.add(Json.createObjectBuilder().add("id", cert.id).add("LABEL", certLABEL));
            }

            JsonObject ret = Json.createObjectBuilder().add("certificates", jsonArrayBuilder).build();
            String retS = ret.toString();

            return retS;

        } catch (Exception ex) {
            ex.printStackTrace();
            return "{\"error\" : \"" + ex.getMessage().replace("\"", "\\\"").replace("\\", "\\\\") + "\"}";
        } finally {
            //SignFactory.getUniqueWebSocketServer().terminate();
        }
    }

    

    public ArrayList<String> showHelp() {

        ArrayList<String> helpList = new ArrayList<String>();

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
        return helpList;
    }
}
