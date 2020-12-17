package aura.ui;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class AuraJSONTabFactory implements IMessageEditorTabFactory {
	
	private IBurpExtenderCallbacks callbacks;
	
	private String auraDataparam;
	private String caption;
	
	public AuraJSONTabFactory(IBurpExtenderCallbacks callbacks){
		this.callbacks = callbacks;
	}

	public AuraJSONTabFactory(IBurpExtenderCallbacks callbacks, String auraDataparam, String caption) {
		this.callbacks = callbacks;
		this.auraDataparam = auraDataparam;
		this.caption = caption;
	}
	
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new AuraJSONTab(controller, editable, this.callbacks, auraDataparam, caption);
	}

}
