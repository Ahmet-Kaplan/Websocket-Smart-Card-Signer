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
var websocket_smartcard_signer = {
  _certId : null,
  _Pin : null,
  _dataToSignList : [],
  _dllList : [],
  _statusLog : [],
  _logHandler : null,
  
  _log : function(msg){
      this._statusLog.push(msg);
      if(this._logHandler != null)
          this._logHandler(msg);
  },
  
  setLogHandler : function(handler){
      if(!(handler instanceof Function))
          throw 'The setLogHandler paramenter must be a function';
      this._logHandler = handler;
      return this;
  },
  
  addcertId : function(certId) {
      this._certId.push(certId);
      return this;
  },
  
  cleancertId : function(){
      this._certId = [];
      return this;
  },

  addPin : function(Pin) {
      this._Pin.push(Pin);
      return this;
  },
  
  cleanpin : function(){
      this._Pin = [];
      return this;
  },

  addDll : function(dllPath) {
      this._dllList.push(dllPath);
      return this;
  },
  
  cleanDll : function(){
      this._dllList = [];
      return this;
  },
  
  addData : function(id, contentB64){
      this._dataToSignList.push({
          id : id,
          contentB64 : contentB64,
          params : null
      });
      return this;
  },
  
  /*
   * 
   * */
  addData : function(id, contentB64, params){
      this._dataToSignList.push({
          id : id,
          contentB64 : contentB64,
          params : params
      });
      return this;
  },
  
  addDataTest : function(){
      this.addData('firstItem', 'dGVzdA==', {
          signPdfAsP7m : false,
          visibleSignature : true,
          pageNumToSign : -1,
          signPosition : 'left'
      });
      return this;
  },
  
  cleanData : function(){
      this._dataToSignList = [];
      return this;
  },
  
  sign : function(resultsHandler, errorHandler){
      var wsEndpoint = 'ws://127.0.0.1:38765/sign';
      if(!(resultsHandler instanceof Function))
          throw 'The sign paramenter must be a function';
      var signService = new WebSocket(wsEndpoint);
      this._log('WebSocket client created');
      signService.onmessage = function(event){
          this._log('Data received from WebSocket: ' + event.data);
          var dataJson = JSON.parse(event.data);
          if(dataJson.error != null)
              errorHandler(dataJson.error);
          else
              resultsHandler(dataJson.dataSigned);
          signService.close();
      }.bind(this);
      signService.onopen = function(){
          var data = {
	      certId : this._certId,
	      Pin : this._Pin,
              dllList : this._dllList,
              dataToSign : this._dataToSignList
          };
          var dataS = JSON.stringify(data);
          signService.send(dataS);
          this._log('Data sent to WebSocket: ' + dataS);
      }.bind(this);
      signService.onclose = function(){
          this._log('Connection closed');
      }.bind(this);
      signService.onerror = function(){
          this._log('Connection error: the WebSocket service ' + wsEndpoint + ' can not be reached.');
          throw 'Connection error: the WebSocket service ' + wsEndpoint + ' can not be reached.';
      }.bind(this);
      return this;
  },
  
  certificates : function(resultsHandler, errorHandler){
      var wsEndpoint = 'ws://127.0.0.1:38766/certificates';
      if(!(resultsHandler instanceof Function))
          throw 'The certificates paramenter must be a function';
      var certService = new WebSocket(wsEndpoint);
      this._log('WebSocket client created');
      certService.onmessage = function(event){
          this._log('Data received from WebSocket: ' + event.data);
          var dataJson = JSON.parse(event.data);
          if(dataJson.error != null)
              errorHandler(dataJson.error);
          else
              resultsHandler(dataJson.dataSigned);
          certService.close();
      }.bind(this);
      certService.onopen = function(){
          certService.send();
          this._log('Data sent to WebSocket: ' + dataS);
      }.bind(this);
      certService.onclose = function(){
          this._log('Connection closed');
      }.bind(this);
      certService.onerror = function(){
          this._log('Connection error: the WebSocket service ' + wsEndpoint + ' can not be reached.');
          throw 'Connection error: the WebSocket service ' + wsEndpoint + ' can not be reached.';
      }.bind(this);
      return this;
  },
  
    getHelp : function(resultsHandler, errorHandler){
      var wsEndpoint = 'ws://127.0.0.1:38767/showInfo';
      if(!(resultsHandler instanceof Function))
          throw 'The certificates paramenter must be a function';
      var helpService = new WebSocket(wsEndpoint);
      this._log('WebSocket client created');
      helpService.onmessage = function(event){
          this._log('Data received from WebSocket: ' + event.data);
          var dataJson = JSON.parse(event.data);
          if(dataJson.error != null)
              errorHandler(dataJson.error);
          else
              resultsHandler(dataJson.dataSigned);
          helpService.close();
      }.bind(this);
      helpService.onopen = function(){
          helpService.send();
          this._log('Data sent to WebSocket: ' + dataS);
      }.bind(this);
      helpService.onclose = function(){
          this._log('Connection closed');
      }.bind(this);
      helpService.onerror = function(){
          this._log('Connection error: the WebSocket service ' + wsEndpoint + ' can not be reached.');
          throw 'Connection error: the WebSocket service ' + wsEndpoint + ' can not be reached.';
      }.bind(this);
      return this;
  }
};
