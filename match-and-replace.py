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
        #request_headers = self.helpers.analyzeRequest(messageInfo).getHeaders()
        body_offset = self.helpers.analyzeRequest(messageInfo).getBodyOffset()

        request = self.helpers.bytesToString(messageInfo.getRequest())
        request_headers = self.helpers.bytesToString(request[:body_offset])
        request_body = self.helpers.bytesToString(request[body_offset:])

        #replace_header = self.replaceRequestHeader(request_headers, "^Cookie.*$", "Auth: ABC=eabc")
        #self.stdout.println(replace_header)
        #messageInfo.setRequest(
        #    "{}{}".format(
        #        replace_header,
        #        request_body
        #    )
        #)

        replace_body = self.replaceRequestBody(request_body, "Age", "Tosi")
        self.stdout.println(replace_body)
        messageInfo.setRequest(
            "{}{}".format(
                request_headers,
                replace_body
            )
        )

    def replaceRequestHeader(self, request_headers, replace_pattern, replace_str):
        if replace_pattern == "":
            header_end = request_headers.rfind(self.NEWLINE)
            return "{}{}{}{}".format(request_headers[:header_end], replace_str, self.NEWLINE, self.NEWLINE)

        for header in request_headers.split(self.NEWLINE):
            if re.match(replace_pattern, header):
                replace_header_start = self.helpers.indexOf(request_headers, header, False, 0, len(request_headers))
                replace_header_end = self.helpers.indexOf(request_headers, self.NEWLINE, False, replace_header_start, len(request_headers))
                break
        
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

class ExtenderTab(ITab):
    TAB_NAME = "M&R Specific target"

    def __init__(self):
        self._mainPanel = JPanel()
        self._mainPanel.setLayout(None)
    
    def getTabCaption(self):
        return self.TAB_NAME
    
    def getUiComponent(self):
        return self._mainPanel