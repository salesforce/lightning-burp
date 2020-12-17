/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Label;
import java.awt.TextField;
import java.io.IOException;

import javax.swing.JPanel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import aura.ActionRequest;
import burp.IBurpExtenderCallbacks;
import java.nio.charset.StandardCharsets;

@SuppressWarnings("serial")
public class ActionRequestPanel extends ActionPanel {

    public IBurpExtenderCallbacks callbacks;
    public boolean isEdited = false;
    public String paramStr;
    private ActionRequest actionRequest;
    private ObjectMapper mapper = new ObjectMapper();
    private TextField controllerField;
    private TextField methodField;
    private boolean editable = true;

    public ActionRequestPanel(IBurpExtenderCallbacks callbacks, ActionRequest ar) {
        this(callbacks, ar, true);
    }

    public ActionRequestPanel(IBurpExtenderCallbacks callbacks, ActionRequest ar, boolean editable) {
        super(callbacks);
        this.actionRequest = ar;
        JsonNode params = ar.getParams();
        this.callbacks = callbacks;
        this.editable = editable;
        String pretty = getPrettyPrintedParams(params);
        BorderLayout panelLayout = new BorderLayout();
        panelLayout.setVgap(5);

        this.setLayout(panelLayout);
        JPanel headerPanel = getHeaderPanel(ar);
        this.add(headerPanel, BorderLayout.PAGE_START);
        createBurpTextPane(pretty);

        this.add(this.textEditor.getComponent());

        this.callbacks.customizeUiComponent(this);
    }

    public String getPrettyPrintedParams(JsonNode params) {
        String pretty;
        try {
            pretty = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(params);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            pretty = e.getOriginalMessage();
        }
        return pretty;
    }

    private void createBurpTextPane(String paramText) {
        this.textEditor.setText(paramText.getBytes(StandardCharsets.UTF_8));
        this.textEditor.setEditable(editable);
    }

    public ActionRequest getActionRequest() {
        return this.actionRequest;
    }

    public boolean isMessageEdited() {
        return this.textEditor.isTextModified();
    }

    public void updateActionBurp() throws JsonProcessingException, IOException {
        if (this.textEditor.isTextModified()) {
            String modifiedText = new String(textEditor.getText(), StandardCharsets.UTF_8);
            JsonNode newParamJson = mapper.readTree(modifiedText);
            this.actionRequest.updateParams((ObjectNode) newParamJson);
        }
        if (!this.actionRequest.calledController.equals(this.controllerField.getText())) {
            this.actionRequest.updateController(this.controllerField.getText());
        }
        if (!this.actionRequest.calledMethod.equals(this.methodField.getText())) {
            this.actionRequest.updateMethod(this.methodField.getText());
        }
    }

    @Deprecated
    public void updateAction() throws JsonProcessingException, IOException {
        if (isEdited) {
            JsonNode newParamJson = mapper.readTree(this.paramStr);
            this.actionRequest.updateParams((ObjectNode) newParamJson);
        }
    }

    private JPanel getHeaderPanel(ActionRequest ar) {
        JPanel headerPanel = new JPanel(new FlowLayout());
        Label controllerLabel = new Label("Controller");
        this.controllerField = new TextField(ar.calledController);
        this.controllerField.setEditable(editable);

        Label methodLabel = new Label("Method");
        this.methodField = new TextField(ar.calledMethod, 20);
        this.methodField.setEditable(editable);

        headerPanel.add(controllerLabel);
        headerPanel.add(controllerField);
        headerPanel.add(methodLabel);
        headerPanel.add(this.methodField);
        return headerPanel;
    }
}
