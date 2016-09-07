/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.mongodb.unison;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Logger;
import org.bson.Document;

import com.mongodb.DB;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.FindIterable;
import com.mongodb.client.ListCollectionsIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoIterable;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import static com.mongodb.client.model.Filters.*;

public class MongoDBTarget implements UserStoreProvider {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MongoDBTarget.class.getName());
	
	String name;
	String database;
	String collectionAttributeName;
	
	String userObjectClass;
	String userRDN;
	String userIdAttribute;
	
	String groupIdAttribute;
	String groupObjectClass;
	String groupRDN;
	String groupMemberAttribute;
	String groupUserIdAttribute;
	
	boolean supportExternalUsers;
	
	MongoClient mongo;

	private ConfigManager cfgMgr;
	

	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		Document doc = new Document();
		String collection = null;
		
		String groupIdAttr = null;
		
		for (String attr : attributes) {
			if (user.getAttribs().containsKey(attr)) {
				if (attr.equalsIgnoreCase(this.collectionAttributeName)) {
					collection = user.getAttribs().get(attr).getValues().get(0);
				} else {
					
					if (attr.equalsIgnoreCase(this.groupUserIdAttribute)) {
						groupIdAttr = user.getAttribs().get(attr).getValues().get(0);
					}
					
					Attribute attribute = user.getAttribs().get(attr);
					if (attribute.getValues().size() == 1) {
						doc.append(attr, attribute.getValues().get(0));
					} else {
						doc.append(attr, attribute.getValues());
					}
				}
			}
		}
		
		doc.append("unisonRdnAttributeName",this.userRDN);
		doc.append("objectClass", this.userObjectClass);
		
		if (collection == null) {
			throw new ProvisioningException("no collection specified");
		} else {
			this.mongo.getDatabase(database).getCollection(collection).insertOne(doc);
		}
		
		this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "_id", doc.get("_id").toString());
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "unisonRdnAttributeName", this.userRDN);
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "collection", collection);
		
		for (String attr : attributes) {
			if (user.getAttribs().containsKey(attr)) {
				if (attr.equalsIgnoreCase(this.collectionAttributeName)) {
					
				} else {
					Attribute attribute = user.getAttribs().get(attr);
					
					for (String val : attribute.getValues()) {
						this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attribute.getName(), val);
					}
					
					
				}
			}
		}
		
		for (String collectionName : mongo.getDatabase(database).listCollectionNames()) {
			FindIterable<Document> groups = mongo.getDatabase(this.database).getCollection(collectionName).find( and (eq("objectClass",this.groupObjectClass),in(this.groupIdAttribute,user.getGroups()))  );
			
			for (Document group : groups) {
				Document newGroup = new Document();
				
				Object o = group.get(this.groupMemberAttribute);
				ArrayList<String> groupMembers = new ArrayList<String>();
				if (o != null) {
					if (o instanceof List) {
						groupMembers.addAll((List) o);
					} else {
						groupMembers.add((String) o);
					}
				}
				
				
				
				if (! groupMembers.contains(user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0))) {
					groupMembers.add(user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0));
					
				}
				
				
				if (groupMembers.size() > 1) {
					newGroup.append(this.groupMemberAttribute, groupMembers);
				} else if (groupMembers.size() == 1) {
					newGroup.append(this.groupMemberAttribute, groupMembers.get(0));
				}
				
				if (groupMembers.size() > 0) {
					Document setGroup = new Document("$set",newGroup);
					mongo.getDatabase(database).getCollection(collectionName).updateOne(eq("_id",group.getObjectId("_id")), setGroup);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", group.getString(this.groupIdAttribute));
					
				}
			}
		}
		
		
		
		
		
		

	}

	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Password not supported");

	}

	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		// TODO Auto-generated method stub

	}

	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		
		if (! user.getAttribs().containsKey(this.groupUserIdAttribute)) {
			HashSet<String> attrs = new HashSet<String>();
			attrs.add(this.userIdAttribute);
			attrs.add(this.groupUserIdAttribute);
			user = this.findUser(user.getUserID(), attrs, request);
			if (user == null) {
				return;
			}
		}
		
		String groupMemberID = user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0);
		
		MongoIterable<String> collections = mongo.getDatabase(this.database).listCollectionNames();
		for (String collection : collections) {
			Document deleted = mongo.getDatabase(this.database).getCollection(collection).findOneAndDelete(and(eq("objectClass",this.userObjectClass),eq(this.userIdAttribute,user.getUserID())));
			if (deleted != null) {
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "_id", deleted.get("_id").toString());
				break;
			}
			
			//check to see if any groups references this object
			FindIterable<Document> groups = mongo.getDatabase(this.database).getCollection(collection).find(and(eq("objectClass",this.groupObjectClass),eq(this.groupMemberAttribute,groupMemberID)));
			for (Document group : groups) {
				Object o = group.get(this.groupMemberAttribute);
				if (o instanceof String) {
					//one value, not mine
					Document newVals = new Document();
					newVals.append(this.groupMemberAttribute, "");
					Document setGroup = new Document("$unset",newVals);
					mongo.getDatabase(database).getCollection(collection).updateOne(eq("_id",group.getObjectId("_id")), setGroup);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", group.getString(this.groupIdAttribute));
				} else {
					List<String> members = (List<String>) o;
					members.remove(groupMemberID);
					Document newVals = new Document();
					newVals.append(this.groupMemberAttribute, members);
					Document setGroup = new Document("$set",newVals);
					mongo.getDatabase(database).getCollection(collection).updateOne(eq("_id",group.getObjectId("_id")), setGroup);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", group.getString(this.groupIdAttribute));
				}
			}
			
		}

	}

	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		MongoIterable<String> colNames = mongo.getDatabase(this.database).listCollectionNames();
		
		for (String col : colNames) {
			FindIterable<Document> searchRes = mongo.getDatabase(this.database).getCollection(col).find(and(eq("objectClass",this.userObjectClass),eq(this.userIdAttribute,userID)));
			Document doc = searchRes.first();
			if (doc != null) {
				User user = new User(userID);
				for (String attrName : attributes) {
					Object o = doc.get(attrName);
					if (o != null) {
						if (o instanceof List) {
							List l = (List) o;
							Attribute attr = new Attribute(attrName);
							attr.getValues().addAll(l);
							user.getAttribs().put(attrName, attr);
						} else {
							Attribute attr = new Attribute(attrName);
							attr.getValues().add(o.toString());
							user.getAttribs().put(attrName, attr);
						}
					}
				}
				
				MongoIterable<String> colNamesG = mongo.getDatabase(this.database).listCollectionNames();
				
				for (String colG : colNamesG) {
					
					FindIterable<Document> searchResG = mongo.getDatabase(this.database).getCollection(colG).find(and(eq("objectClass",this.groupObjectClass),eq(this.groupMemberAttribute,doc.getString(this.groupUserIdAttribute))));
					for (Document g : searchResG) {
						user.getGroups().add(g.getString(this.groupIdAttribute));
					}
				}
				
				
				return user;
			}
		}
		
		//if we're here, there's no entry in the mongo
		if (this.supportExternalUsers) {
			try {
				LDAPSearchResults res = this.searchExternalUser(userID);
				if (! res.hasMore()) {
					return null;
				} else {
					LDAPEntry ldap = res.next();
					LDAPAttribute attr = ldap.getAttribute(this.groupUserIdAttribute);
					if (attr == null) {
						return null;
					}
					String groupMemberID = attr.getStringValue();
					User user = new User(userID);
					user.getAttribs().put(this.userIdAttribute, new Attribute(this.userIdAttribute,userID));
					
					MongoIterable<String> colNamesG = mongo.getDatabase(this.database).listCollectionNames();
					
					for (String colG : colNamesG) {
						
						FindIterable<Document> searchResG = mongo.getDatabase(this.database).getCollection(colG).find(and(eq("objectClass",this.groupObjectClass),eq(this.groupMemberAttribute,groupMemberID)));
						for (Document g : searchResG) {
							user.getGroups().add(g.getString(this.groupIdAttribute));
						}
					}
					
					if (user.getGroups().isEmpty()) {
						return null;
					} else {
						return user;
					}
					
					
					
				}
			} catch (LDAPException e) {
				throw new ProvisioningException("Error searching for external user",e);
			}
		} else {
			return null;
		}
		
		
		
	}
	
	private LDAPSearchResults searchExternalUser(String userID)
			throws LDAPException {
		LDAPSearchResults res;
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add(this.groupUserIdAttribute);
		StringBuffer filter = new StringBuffer();
		filter.append("(").append(this.userIdAttribute).append("=").append(userID).append(")");
		res = this.cfgMgr.getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, filter.toString(), attrs);
		return res;
	}

	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.cfgMgr = cfgMgr;
		this.name = name;
		this.mongo = new MongoClient(new MongoClientURI(cfg.get("url").getValues().get(0)));
		this.database = cfg.get("database").getValues().get(0);
		
		this.userObjectClass = cfg.get("userObjectClass").getValues().get(0);
		this.userRDN = cfg.get("userRDN").getValues().get(0);
		this.userIdAttribute = cfg.get("userIdAttribute").getValues().get(0);
		this.groupIdAttribute = cfg.get("groupIdAttribute").getValues().get(0);
		this.groupObjectClass = cfg.get("groupObjectClass").getValues().get(0);
		this.groupRDN = cfg.get("groupRDN").getValues().get(0);
		this.groupMemberAttribute = cfg.get("groupMemberAttribute").getValues().get(0);
		this.groupUserIdAttribute = cfg.get("groupUserIdAttribute").getValues().get(0);
		this.supportExternalUsers = cfg.get("supportExternalUsers").getValues().get(0).equalsIgnoreCase("true");
		this.collectionAttributeName = cfg.get("collectionAttributeName").getValues().get(0);
		
		cfgMgr.addThread(new StopableThread() {

			public void run() {
				
				
			}

			public void stop() {
				mongo.close();
				
			}});

	}

}
