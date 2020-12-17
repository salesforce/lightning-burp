/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import java.awt.Component;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;

import com.fasterxml.jackson.core.JsonProcessingException;

import aura.ActionRequest;
import aura.AuraMessage;
import aura.AuraResponse;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITextEditor;
import java.nio.charset.StandardCharsets;

public class AuraTab implements IMessageEditorTab {

    private static final String AURA_DATAPARAM = "message";
    private static final String AURA_INDICATOR = "aura.token";
    private static final String AURA_RESPONSE_START = "while(1)";

    public JTabbedPane pane;
    public byte[] content;
    private AuraMessage currentAuraMessage;

    private boolean editable;
    private boolean isEdited = false;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public Map<String, ActionRequestPanel> actionRequestTabs = new HashMap<String, ActionRequestPanel>();
    public Map<String, ActionResponsePanel> actionResponseTabs = new HashMap<String, ActionResponsePanel>();
    private IHttpService httpService;

    public AuraTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks) {
        this.pane = new JTabbedPane();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.httpService = controller.getHttpService();
        this.editable = editable;
    }

    @Override
    public String getTabCaption() {
        return "Aura Actions";
    }

    @Override
    public Component getUiComponent() {
        return this.pane;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return (isRequest && isRequestEnabled(content)) || isResponseEnabled(content);
    }

    private boolean isRequestEnabled(byte[] content) {
        boolean auraMessage = (null != helpers.getRequestParameter(content, AURA_INDICATOR));

        if (this.httpService != null) {
            boolean auraEndpoint = true; // true until proven wrong
            IRequestInfo request = helpers.analyzeRequest(this.httpService, content);

            if (request.getUrl() != null) {
                auraEndpoint = request.getUrl().getPath().contains("/aura");
            }
            return auraEndpoint && auraMessage;
        } else {
            return auraMessage;
        }
    }

    private boolean isResponseEnabled(byte[] content) {
        IResponseInfo response = helpers.analyzeResponse(content);
        String mimeType = response.getStatedMimeType();
        if (!mimeType.equals("JSON")) {
            return false;
        }
        String body = helpers.bytesToString(content);
        body = body.substring(response.getBodyOffset());
        return body.substring(0, AURA_RESPONSE_START.length()).equals(AURA_RESPONSE_START);
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (isRequest) {
            requestSetup(content);
        } else {
            responseSetup(content);
        }
    }

    public void requestSetup(byte[] content) {
        this.cleanTab();
        this.content = content;
        IParameter param = helpers.getRequestParameter(content, AURA_DATAPARAM);
        String jsonText = Utils.urlDecode(param.getValue());
        // throw jsonText into extra pannel

        try {
            this.currentAuraMessage = new AuraMessage(jsonText);
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        Iterator<String> iter = currentAuraMessage.actionMap.keySet().iterator();
        while (iter.hasNext()) {
            String nextId = iter.next();
            ActionRequest nextActionRequest = currentAuraMessage.actionMap.get(nextId);
            ActionRequestPanel arPanel = new ActionRequestPanel(this.callbacks, nextActionRequest, editable);

            this.actionRequestTabs.put(nextId, arPanel);
            this.pane.add(nextId + "::" + nextActionRequest.calledMethod, arPanel);
        }
    }

    public void responseSetup(byte[] content) {
        this.cleanTab();

        String body = getResponseBody(content);
        AuraResponse response;
        try {
            response = new AuraResponse(body);
        } catch (JsonProcessingException e) {
            e.printStackTrace();

            // Invalid JSON.  happens when we do "key": function()
            // Jackson doesn't support parsing this, so we will just return the string then
            ITextEditor te = callbacks.createTextEditor();
            te.setEditable(false);
            te.setText(body.getBytes(StandardCharsets.UTF_8));
            this.pane.add("Invalid JSON", te.getComponent());
            return;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
        Iterator<String> responseIter = response.responseActionMap.keySet().iterator();
        while (responseIter.hasNext()) {
            String nextActionId = responseIter.next();
            ActionResponsePanel nextPanel = new ActionResponsePanel(this.callbacks, response.responseActionMap.get(nextActionId));
            this.pane.add(nextActionId, nextPanel);
        }
    }

    private String getResponseBody(byte[] content) {
        IResponseInfo responseBody = this.helpers.analyzeResponse(content);
        String responseStr = this.helpers.bytesToString(content);
        int bodyOffset = responseBody.getBodyOffset();
        int bodyFinal = responseStr.length();
        assert (bodyFinal > bodyOffset);
        return responseStr.substring(bodyOffset, bodyFinal);
    }

    private void cleanTab() {
        pane.removeAll();
        pane.revalidate();
    }

    private void updateTabActions() {
        Iterator<String> actionIter = this.actionRequestTabs.keySet().iterator();
        while (actionIter.hasNext()) {
            ActionRequestPanel nextActionRequestTab = this.actionRequestTabs.get(actionIter.next());
            try {
                nextActionRequestTab.updateActionBurp();
            } catch (JsonProcessingException e) {
                JOptionPane.showMessageDialog(this.pane, "Invalid JSON entered, using original payload");
                callbacks.issueAlert("Invalid JSON entered, using original payload");
                e.printStackTrace();
            } catch (IOException e) {
                callbacks.issueAlert("IOException in Aura Actions tab");
                e.printStackTrace();
            }
        }
    }

    private byte[] getNewContent(String messageStr) {
        messageStr = Utils.urlEncode(messageStr);
        IParameter newParam = helpers.buildParameter(AURA_DATAPARAM, messageStr, IParameter.PARAM_BODY);
        return helpers.updateParameter(content, newParam);
    }

    @Override
    public byte[] getMessage() {
        cleanTab();
        updateTabActions();

        if (this.currentAuraMessage.isEdited()) {
            isEdited = true;
        }

        String auraMessageStr;
        try {
            auraMessageStr = this.currentAuraMessage.getAuraRequest();
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return this.content;
        }

        this.content = getNewContent(auraMessageStr);
        return this.content;
    }

    @Override
    public boolean isModified() {
        return isEdited;
    }

    @Override
    public byte[] getSelectedData() {
        if (pane.getSelectedIndex() == -1) {
            return null;
        } else {
            int actionIndex = pane.getSelectedIndex();
            ActionPanel activeComponent = (ActionPanel) pane.getComponentAt(actionIndex);
            return activeComponent.getSelectedText();
        }
    }

}
