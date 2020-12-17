/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class AuraMessage {
	private ObjectMapper mapper = new ObjectMapper();
	public ArrayNode actions;
	public Map<String,ActionRequest> actionMap = new HashMap<String,ActionRequest>();
	public ObjectNode auraMessage;
	private boolean edited = false;
	
	public AuraMessage(){
	}
	
	public AuraMessage(String jsonString) throws JsonProcessingException, IOException {
		JsonNode parsedNode = mapper.readTree(jsonString);
		this.auraMessage = (ObjectNode)parsedNode;

		if(this.auraMessage.has("actions")){
			this.actions = (ArrayNode)this.auraMessage.get("actions");
			
			Iterator<JsonNode> iter = this.actions.iterator();
			while(iter.hasNext()){
				ObjectNode next = (ObjectNode)iter.next();	
				ActionRequest nextAction = new ActionRequest(next,this);
				actionMap.put(nextAction.id, nextAction);
			}
		}
	}

	@Deprecated
	public void parseRequest(String jsonString) throws JsonProcessingException, IOException{
		JsonNode parsedNode = mapper.readTree(jsonString);
		this.auraMessage = (ObjectNode)parsedNode;

		if(this.auraMessage.has("actions")){
			this.actions = (ArrayNode)this.auraMessage.get("actions");
			
			Iterator<JsonNode> iter = this.actions.iterator();
			while(iter.hasNext()){
				ObjectNode next = (ObjectNode)iter.next();	
				ActionRequest nextAction = new ActionRequest(next,this);
				actionMap.put(nextAction.id, nextAction);
			}
		} 
	}
	
	public void updateActionRequest(String id, ActionRequest newActionRequest){
		this.edited = true;
		actionMap.put(id, newActionRequest);
	}
	
	public void parseResponse(String jsonString) throws JsonProcessingException, IOException{
		ObjectMapper om = new ObjectMapper();
		om.readTree(jsonString);
	}

	public String getAuraRequest() throws JsonProcessingException{
		if(this.edited){
			JsonNodeFactory factory = JsonNodeFactory.instance;
			ArrayNode newActions = new ArrayNode(factory);
			Iterator<String> actionIter = this.actionMap.keySet().iterator();
			while(actionIter.hasNext()){
				ActionRequest nextAr = this.actionMap.get(actionIter.next());
				newActions.add(nextAr.root);
			}
			this.auraMessage.replace("actions", newActions);
		}
		return mapper.writer().writeValueAsString(this.auraMessage);
	}
	
	public ObjectNode parseParamString(String jsonString) throws JsonProcessingException, IOException{
		ObjectMapper om = new ObjectMapper();
		ObjectNode res = (ObjectNode)om.readTree(jsonString);
		return res;
	}
	
	public boolean isEdited(){
		return edited;
	}
}
