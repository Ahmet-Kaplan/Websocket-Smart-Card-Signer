/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package df.sign;

import df.sign.server.SignServer;
import df.sign.server.getCertificates;
import df.sign.server.showInfo;
import static spark.Spark.*;

/**
 *
 * @author akaplan
 */
public class RestServer {

    public static void main(String[] args) {

        try{
            SignUtils.initLog();
        port(38765); 

        get("/certificates","application/json", (request, response) -> {
            getCertificates newCert = new getCertificates(SignFactory.getUniqueEngine());
            return newCert.getCertificates(request,response);
        });

        get("/showInfo","application/json", (request, response) -> {
            showInfo newInfo = new showInfo(SignFactory.getUniqueEngine());
            return newInfo.showHelp(request,response);
        });

        post("/sign","application/json", (request, response) -> {
            SignServer newSign = new SignServer(SignFactory.getUniqueEngine());
            return newSign.sign(request,response);
        });

        
        
        post("/hello", (request, response) ->
            "Hello World: " + request.body()
        );
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }
    
}

