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
package df.sign.server;

import df.sign.SignEngine;
import df.sign.SignUtils;
import java.util.ArrayList;
import df.sign.pkcs11.CertificateData;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import spark.Request;
import spark.Response;

public class getCertificates {

    
    public SignEngine signEngine = null;

    public boolean readAllCertificates = false;

    public getCertificates(SignEngine signEngine) {
        this.signEngine = signEngine;
    }
    
    public String getCertificates(Request request, Response response) {
        try {

            ArrayList<CertificateData> certList = new ArrayList<CertificateData>();
            try {
                certList = signEngine.loadSmartCardCertificateList(readAllCertificates).certificateList;
            } catch (Exception e) {
                e.printStackTrace();
            }

            JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
            JsonObjectBuilder certParams = Json.createObjectBuilder();
            for (CertificateData certItem : certList) {
                // Certificate Informations such as ID and Label
                certParams = Json.createObjectBuilder();
                certParams.add("id", certItem.id);
                certParams.add("Label", new String(SignUtils.base64Encode(certItem.certLABEL), "UTF-8"));
                certParams.add("SubjectDN", certItem.cert.asX509Certificate().getSubjectDN().getName());
                certParams.add("IssuerDN", certItem.cert.asX509Certificate().getIssuerDN().getName());
                certParams.add("StartDate", certItem.cert.asX509Certificate().getNotBefore().toString());
                certParams.add("ExpiredDate", certItem.cert.asX509Certificate().getNotAfter().toString());
                certParams.add("SerialNumber", certItem.cert.getSerialNumber());
                jsonArrayBuilder.add(certParams);
            }

            JsonObject ret = Json.createObjectBuilder().add("certificates", jsonArrayBuilder).build();
            return ret.toString();

        } catch (Exception ex) {
            ex.printStackTrace();
            return "{\"error\" : \"" + ex.getMessage().replace("\"", "\\\"").replace("\\", "\\\\") + "\"}";
            
        } finally {
            //SignFactory.getUniqueWebSocketServer().terminate();
        }
    }

}
