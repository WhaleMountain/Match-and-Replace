# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File
from javax.swing.table import TableModel
from javax.swing.table import DefaultTableModel
from java.awt import Insets
from java.awt import Dimension, Color
from java.awt.event import ActionListener
import json
import re

class BurpExtender(IBurpExtender, IProxyListener, ITab, ActionListener):
    EXTENSION_NAME = "M&R Specific target"
    TAB_NAME       = "M&R Config"
    NEWLINE        = "\r\n"

    def __init__(self):
        # URLの正規表現
        url_pattern = "https?://"
        self.url_regex = re.compile(url_pattern)

        self.replace_targets = {
            "https://example.com/": [
                {
                    "Comment": "Sample Math and Replace",
                    "Enable": True,
                    "Method": "GET",
                    "Type": "Request header",
                    "Pattern": "^Cookie.*$",
                    "Replace": "Cookie: Test=test"
                }
            ]
        }
        init_json = json.dumps(self.replace_targets, sort_keys=True, indent=4)

        # GUI
        self._main_panel = JPanel()
        self._main_panel.setLayout(None)

        config_panel = JPanel()
        title = JLabel("Math and Replace for Specific target")
        self._save_btn = JButton("Save")
        self._import_btn = JButton("Import")
        self._export_btn = JButton("Export")

        self._json_chooser = JFileChooser()
        self._json_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        self._json_chooser.setAcceptAllFileFilterUsed(False)
        extFilter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
        self._json_chooser.addChoosableFileFilter(extFilter)

        config_panel.setBounds(279, 50, 500, 50)

        self._save_btn.addActionListener(self)
        self._import_btn.addActionListener(self)
        self._export_btn.addActionListener(self)

        config_panel.add(title)
        config_panel.add(self._save_btn)
        config_panel.add(self._import_btn)
        config_panel.add(self._export_btn)

        self._json_area = JTextArea(init_json)
        self._json_area.setWrapStyleWord(True) # 単語単位で折り返し
        self._json_area.setCaretPosition(len(init_json))
        self._json_area.setTabSize(2)
        self._json_area.setMargin(Insets(5, 5, 5, 5))
        scroll_pane = JScrollPane(self._json_area)
        scroll_pane.setBounds(300, 130, 1000, 800)

        self._main_panel.add(config_panel)
        self._main_panel.add(scroll_pane)

    def	registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.addSuiteTab(self)
        callbacks.registerProxyListener(self)

    def getTabCaption(self):
        return self.TAB_NAME
    
    def getUiComponent(self):
        return self._main_panel

    def actionPerformed(self, event):
        if event.getSource() is self._save_btn:
            try:
                self.replace_targets = json.loads(self._json_area.getText())
            except ValueError:
                self.callbacks.printError("Parse error")
                return

        # Clicked Import Button
        elif event.getSource() is self._import_btn:
            self._json_chooser.showOpenDialog(event.getSource())
            import_file_path = self._json_chooser.getSelectedFile().getAbsolutePath()
            with open(import_file_path, 'r') as f:
                try:
                    import_data = json.loads(f.read())
                except:
                    self.callbacks.printError("Parse error")
                    return
            
            self._json_area.setText(json.dumps(import_data, sort_keys=True, indent=4))
            self.replace_targets = import_data

        # Clicked Export Button
        elif event.getSource() is self._export_btn:
            self._json_chooser.showSaveDialog(event.getSource())
            export_file_path = self._json_chooser.getSelectedFile().getAbsolutePath()
            file_ext = self._json_chooser.getSelectedFile().getName().split(".")[-1]
            if file_ext.lower() != "json":
                export_file_path = '{}.json'.format(export_file_path)
                self._json_chooser.setSelectedFile(File(export_file_path))

            # 上書き保存の確認
            if self._json_chooser.getSelectedFile().exists():
                message = "{} already exists.\nDo you want to replace it?".format(export_file_path)
                ans = JOptionPane.showConfirmDialog(None, message, "Save As", JOptionPane.YES_NO_OPTION)
                if (ans == JOptionPane.NO_OPTION):
                    return

            export_data = self._json_area.getText()
            with open(export_file_path, 'w') as f:
                f.write(export_data)
    
    def processProxyMessage(self, messageIsRequest, message): 
        if not messageIsRequest:
            return
        
        messageInfo = message.getMessageInfo()
        request = self.helpers.bytesToString(messageInfo.getRequest())
        requestInfo = self.helpers.analyzeRequest(messageInfo.getHttpService(), request)
        url         = requestInfo.getUrl()
        method      = requestInfo.getMethod()

        replace_terms = []
        try:
            replace_terms = self.replace_targets["{}://{}{}".format(url.getProtocol(), url.getHost(), url.getPath())]
        except KeyError:
            self.callbacks.printOutput("No match")

        body_offset = self.helpers.analyzeRequest(messageInfo).getBodyOffset()
        request_headers = self.helpers.bytesToString(request[:body_offset])
        request_body = self.helpers.bytesToString(request[body_offset:])

        includeBody = False
        for terms in replace_terms:
            if not terms["Enable"] or terms["Method"] != method:
                continue

            if terms["Type"] == "Request body":
                includeBody = True
                request_body = self.replaceRequestBody(request_body, terms["Pattern"], terms["Replace"])

            elif terms["Type"] == "Request header":
                request_headers = self.replaceRequestHeader(request_headers, terms["Pattern"], terms["Replace"])

        # Bodyを書き換えた際はContent-Lengthを更新する
        if includeBody:
            messageInfo.setRequest(
                self.updateContentLength("{}{}".format(request_headers, request_body))
            )

        else:
            messageInfo.setRequest(
                "{}{}".format(request_headers, request_body)
            )

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