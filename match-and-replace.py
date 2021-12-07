# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JPanel, JScrollPane, JButton, JLabel, JMenuItem, JComboBox, JTable, JTextField, JFileChooser, JOptionPane
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import TableModel
from javax.swing.table import DefaultTableModel
from java.awt import Dimension, Color
from java.awt.event import ActionListener
import json
import re

class BurpExtender(IBurpExtender, IProxyListener, ActionListener):
    EXTENSION_NAME = "M&R Specific target"
    NEWLINE        = "\r\n"

    def __init__(self):
        # URLの正規表現
        url_pattern = "https?://"
        self.url_regex = re.compile(url_pattern)

        self.sample_data = {
            "http://localhost/": [
                {
                    "isEnable": False,
                    "type": "Request body",
                    "matchPattern": "",
                    "replaceString": '{"user":"sato","password":"sato123"}'
                },
                {
                    "isEnable": True,
                    "type": "Request header",
                    "matchPattern": "^Cookie.*$",
                    "replaceString": "Cookie: Auth=aa"
                }
            ],

            "http://myapp.com/api/auth/login": [
                {
                    "isEnable": True,
                    "type": "Request body",
                    "matchPattern": '{"email":".*","password":".*"}',
                    "replaceString": '{"email":"user2@example.com","password":"password"}'
                },
                {
                    "isEnable": True,
                    "type": "Request header",
                    "matchPattern": "^Accept.*$",
                    "replaceString": ""
                },
                {
                    "isEnable": True,
                    "type": "Request header",
                    "matchPattern": "^If-None-Match.*$",
                    "replaceString": ""
                },
                {
                    "isEnable": True,
                    "type": "Request header",
                    "matchPattern": "^If-Modified-Since.*$",
                    "replaceString": ""
                }
            ],
            }

    def	registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        self.stdout    = PrintWriter(callbacks.getStdout(), True) #self.stdout.println()

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.addSuiteTab(ExtenderTab())
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message): 
        if not messageIsRequest:
            return
        
        messageInfo = message.getMessageInfo()
        request = self.helpers.bytesToString(messageInfo.getRequest())
        requestInfo = self.helpers.analyzeRequest(messageInfo.getHttpService(), request)
        url         = requestInfo.getUrl()

        if not self.callbacks.isInScope(url) or requestInfo.getMethod() == "OPTIONS":
            return 

        data = self.sample_data["{}://{}{}".format(url.getProtocol(), url.getHost(), url.getPath())]
        body_offset = self.helpers.analyzeRequest(messageInfo).getBodyOffset()
        request_headers = self.helpers.bytesToString(request[:body_offset])
        request_body = self.helpers.bytesToString(request[body_offset:])

        for d in data:
            if not d["isEnable"]:
                continue

            if d["type"] == "Request body":
                request_body = self.replaceRequestBody(request_body, d["matchPattern"], d["replaceString"])

            elif d["type"] == "Request header":
                request_headers = self.replaceRequestHeader(request_headers, d["matchPattern"], d["replaceString"])

        # bodyがあるときはContent-Lengthの更新必要
        messageInfo.setRequest(self.updateContentLength("{}{}".format(request_headers, request_body)))

        #messageInfo.setRequest(
        #    "{}{}".format(
        #        request_headers,
        #        request_body
        #    )
        #)

    def replaceRequestHeader(self, request_headers, replace_pattern, replace_str):
        if replace_pattern == "":
            header_last = request_headers.rfind(self.NEWLINE)
            return "{}{}{}{}".format(request_headers[:header_last], replace_str, self.NEWLINE, self.NEWLINE)

        regex = re.compile(replace_pattern)
        replace_header_start = -1
        replace_header_end = -1
        for header in request_headers.split(self.NEWLINE):
            if regex.match(header):
                replace_header_start = self.helpers.indexOf(request_headers, header, False, 0, len(request_headers))
                replace_header_end = self.helpers.indexOf(request_headers, self.NEWLINE, False, replace_header_start, len(request_headers))
                break
        
        if replace_header_start == -1 and replace_header_end == -1:
            return request_headers

        # \r\n も削除対象
        if replace_str == "":
            replace_header_end += 2

        return "{}{}{}".format(
            request_headers[:replace_header_start],
            replace_str,
            request_headers[replace_header_end:]
        )

    def replaceRequestBody(self, request_body, replace_pattern, replace_str):
        if replace_pattern == "":
            return "{}{}".format(request_body, replace_str)
        return re.sub(replace_pattern, replace_str, request_body)

    def replaceResponseHeader(self, response_headers, replace_pattern, replace_str):
        pass
    
    def replaceResponseBody(self, response_body, replace_pattern, replace_str):
        pass

    def updateContentLength(self, request):
        body_offset = self.helpers.indexOf(request, "{}{}".format(self.NEWLINE, self.NEWLINE), False, 0, len(request)) + 4
        request_headers = self.helpers.bytesToString(request[:body_offset])
        request_body = self.helpers.bytesToString(request[body_offset:])

        content_length = "Content-Length: {}".format(len(request_body))
        content_length_start = -1
        content_length_end = -1
        for header in request_headers.split(self.NEWLINE):
            if header.startswith("Content-Length"):
                content_length_start = self.helpers.indexOf(request_headers, header, False, 0, len(request_headers))
                content_length_end = self.helpers.indexOf(request_headers, self.NEWLINE, False, content_length_start, len(request_headers))
                break

        return "{}{}{}{}".format(
            request_headers[:content_length_start],
            content_length,
            request_headers[content_length_end:],
            request_body
        )

class ExtenderTab(ITab):
    TAB_NAME = "M&R Specific target"

    def __init__(self):
        self._main_panel = JPanel()
        self._main_panel.setLayout(None)
    
    def getTabCaption(self):
        return self.TAB_NAME
    
    def getUiComponent(self):
        return self._main_panel