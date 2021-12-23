# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JMenuItem
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File
from java.io import PrintWriter
from java.awt import Insets
from java.awt import Font
from java.awt.event import ActionListener
import json
import re

class BurpExtender(IBurpExtender, IProxyListener, ITab, IContextMenuFactory, IContextMenuInvocation, ActionListener):
    EXTENSION_NAME = "M&R Rules"
    TAB_NAME       = "M&R Rules"
    MENU_NAME      = "Add rule"
    TARGETS_KEYS   = ("Enable", "Method", "Comment", "Pattern", "Replace", "Type")

    def __init__(self):
        self.replace_targets = {
            "https://example.com/": [
                {
                    "Comment": "Sample Math and Replace",
                    "Enable": True,
                    "Method": "GET",
                    "Type": "Request header",
                    "Pattern": "^Referer.*$",
                    "Replace": "Referer: https://example.com/"
                }
            ]
        }
        init_json = json.dumps(self.replace_targets, sort_keys=True, indent=4)

        # GUI
        self._main_panel = JPanel()
        self._main_panel.setLayout(None)

        config_panel = JPanel()
        config_panel.setBounds(240, 50, 500, 50)
        title = JLabel("Math and Replace Rules")
        self._save_btn = JButton("Save")
        self._import_btn = JButton("Import")
        self._export_btn = JButton("Export")

        self._json_chooser = JFileChooser()
        self._json_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        self._json_chooser.setAcceptAllFileFilterUsed(False)
        extFilter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
        self._json_chooser.addChoosableFileFilter(extFilter)

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
        self._json_area.setFont(Font(Font.DIALOG_INPUT, Font.PLAIN, 16))
        scroll_pane = JScrollPane(self._json_area)
        scroll_pane.setBounds(300, 130, 1000, 800)

        self._main_panel.add(config_panel)
        self._main_panel.add(scroll_pane)

    def	registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True) #self._stdout.println()

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerProxyListener(self)

    def getTabCaption(self):
        return self.TAB_NAME
    
    def getUiComponent(self):
        return self._main_panel

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem(self.MENU_NAME, actionPerformed=lambda x, inv=invocation: self.menuActionAdd(inv)))
        return menu

    def menuActionAdd(self, inv):
        messages = inv.getSelectedMessages()
        for messageInfo in messages:
            requestInfo = self.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            url = requestInfo.getUrl()
            add_target_url = "{}://{}{}".format(url.getProtocol(), url.getHost(), url.getPath())
            self.replace_targets.setdefault(add_target_url, [{}])
        if len(messages) > 0:
            self._json_area.setText(json.dumps(self.replace_targets, sort_keys=True, indent=4))

    def actionPerformed(self, event):
        # Clicked Save Button
        if event.getSource() is self._save_btn:
            try:
                self.replace_targets = json.loads(self._json_area.getText())
            except ValueError:
                self.callbacks.printError("Parse error")
                return

        # Clicked Import Button
        elif event.getSource() is self._import_btn:
            dialog_ans = self._json_chooser.showOpenDialog(event.getSource())
            if dialog_ans == JFileChooser.CANCEL_OPTION:
                return
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
            dialog_ans = self._json_chooser.showSaveDialog(event.getSource())
            if dialog_ans == JFileChooser.CANCEL_OPTION:
                return
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
        messageInfo = message.getMessageInfo()
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()

        requestInfo = self.helpers.analyzeRequest(messageInfo.getHttpService(), request)
        url = requestInfo.getUrl()
        method = requestInfo.getMethod()

        replace_rules = []
        try:
            replace_rules = self.replace_targets["{}://{}{}".format(url.getProtocol(), url.getHost(), url.getPath())]
        except KeyError:
            return

        # リクエストのMatch and Replace
        if messageIsRequest:
            request_body_offset = self.helpers.analyzeRequest(messageInfo).getBodyOffset()
            request_headers = self.helpers.analyzeRequest(messageInfo).getHeaders()
            request_body = self.helpers.bytesToString(request[request_body_offset:])

            for rule in replace_rules:
                if set(self.TARGETS_KEYS) != set(rule.keys()):
                    continue

                if not rule["Enable"] or rule["Method"] != method:
                    continue

                if rule["Type"] == "Request header":
                    request_headers = self.replaceRequestHeader(list(request_headers), rule["Pattern"], rule["Replace"])

                elif rule["Type"] == "Request body":
                    request_body = self.replaceRequestBody(request_body, rule["Pattern"], rule["Replace"])

            replaced_request = self.helpers.buildHttpMessage(request_headers, request_body)
            messageInfo.setRequest(replaced_request)

        # レスポンスのMatch and Replace
        elif response != None:
            response_body_offset = self.helpers.analyzeResponse(response).getBodyOffset()
            response_headers = self.helpers.analyzeResponse(response).getHeaders()
            response_body = self.helpers.bytesToString(response[response_body_offset:])

            for rule in replace_rules:
                if set(self.TARGETS_KEYS) != set(rule.keys()):
                    continue

                if not rule["Enable"] or rule["Method"] != method:
                    continue

                if rule["Type"] == "Response header":
                    response_headers = self.replaceResponseHeader(list(response_headers), rule["Pattern"], rule["Replace"])

                elif rule["Type"] == "Response body":
                    response_body = self.replaceResponseBody(response_body, rule["Pattern"], rule["Replace"])

            replaced_response = self.helpers.buildHttpMessage(response_headers, response_body)
            messageInfo.setResponse(replaced_response)


    def replaceRequestHeader(self, request_headers, replace_pattern, replace_str):
        if replace_pattern == "":
            request_headers.append(replace_str)
            return request_headers

        regex = re.compile(replace_pattern)
        for idx, header in enumerate(request_headers):
            if regex.match(header):
                if replace_str == "":
                    request_headers.remove(request_headers[idx])
                    break
                request_headers[idx] = replace_str
                break

        return request_headers

    def replaceRequestBody(self, request_body, replace_pattern, replace_str):
        if replace_pattern == "":
            return "{}{}".format(request_body, replace_str)
        return re.sub(replace_pattern, replace_str, request_body)


    def replaceResponseHeader(self, response_headers, replace_pattern, replace_str):
        if replace_pattern == "":
            response_headers.append(replace_str)
            return response_headers

        regex = re.compile(replace_pattern)
        for idx, header in enumerate(response_headers):
            if regex.match(header):
                if replace_str == "":
                    response_headers.remove(response_headers[idx])
                    break
                response_headers[idx] = replace_str
                break

        return response_headers
    
    def replaceResponseBody(self, response_body, replace_pattern, replace_str):
        if replace_pattern == "":
            return "{}{}".format(response_body, replace_str)
        return re.sub(replace_pattern, replace_str, response_body)