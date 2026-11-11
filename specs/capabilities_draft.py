"""
工具能力声明表 —— **初稿（机器生成，人工待审）**

生成器：exercises/ex06_capability_draft.py
来源：A2AServer 的 AST 实测（exercises/ex05_tool_audit.py）

⚠️ 这份表是**初稿**，人工审阅要点：
   1. `writes` 目前是粗分类（db / memory / file / ui），要精确到具体资源
      （如 health_records / medication_schedule）需要人工细化；
   2. mock 工具的 `writes` 留空 —— 它被实现的那天，CI 对账会红；
   3. `ui_content_from_llm` 是污点分析的近似结果，要人眼确认一遍；
   4. 每条都过一遍，改完把 TODO 去掉；
   5. **本表只覆盖「注册面」（@mcp.tool()），不覆盖「提示词」** ——
      提示词是给人写的、机器校验不了的那份能力清单，两边会漂。
      靶场里的现成例子：`get_health_records_overview` 在
      `HealthAdvisor/memory_enhanced_agent_prompt.md:57,73,84` 被点名要调，
      但 `a2a_integration_tool.py:153` 上**没有 @mcp.tool()** → 运行时不存在，
      模型按提示词发起的调用必然失败；而那个函数内部还埋着必崩的 NameError
      和一次「崩之前的出网」——补一个装饰器就同时复活两者。
      所以：**审这份表的同时，要对一遍提示词**（F-020）。

字段语义见 specs/tool_capabilities.py 的 `Capability` 定义，
规则与合并算法见 specs/tool_capabilities.md。

四处**不靠名字、只靠实测**才能看出来的例子（先读这几个再填表）：
   · list_medical_kb_documents —— 名字是只读动词，但它调的 `_ensure_rag_schema`
     会执行 CREATE TABLE / ALTER TABLE → ddl=True
   · get_medication_overview 等 4 个 —— 名字是 get，但出网目标由 LLM 填
   · ask_agent_in_page —— 不碰库、不发 HTTP，但前端会替它发起一次 agent 调用
   · get_health_records_overview —— 名字像工具，但**根本没注册**，只有提示词在叫它；
     AST 扫注册面时正确地漏掉了它，所以它不进这张表（漏得对）
"""
from __future__ import annotations

# 抄进靶场时改成：from .tool_capabilities import Capability
from tool_capabilities import Capability

# 工具名 → 能力声明
TOOL_CAPABILITIES: dict[str, Capability] = {
    "get_medication_overview": Capability(writes=('ui',), egress=('http', 'agent'), egress_target_from_llm=True, ui_actions=('setData',), ui_content_from_llm=True,),  # backend/HealthAdvisor/mcpserver/a2a_integration_tool.py:169
    "get_visit_summary_overview": Capability(writes=('ui',), egress=('http', 'agent'), egress_target_from_llm=True, ui_actions=('setData',), ui_content_from_llm=True,),  # backend/HealthAdvisor/mcpserver/a2a_integration_tool.py:199
    "aggregate_health_report": Capability(writes=('ui',), egress=('http', 'agent'), egress_target_from_llm=True, ui_actions=('setData',),),  # backend/HealthAdvisor/mcpserver/a2a_integration_tool.py:226
    "get_health_records_history": Capability(writes=('ui',), egress=('http', 'agent'), egress_target_from_llm=True, ui_actions=('setData',), ui_content_from_llm=True,),  # backend/HealthAdvisor/mcpserver/a2a_integration_tool.py:244
    "generate_consultation_summary": Capability(writes=('ui',), egress=('agent',),),  # backend/HealthAdvisor/mcpserver/a2a_integration_tool.py:327
    "save_consultation": Capability(writes=('db',),),  # backend/HealthAdvisor/mcpserver/database_tool.py:103
    "get_consultation_history": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "analyze_symptoms": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_disease_info": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "generate_health_assessment": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "ai_medical_diagnosis": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "search_symptom_info": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "search_medication_info": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_health_tips": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "analyze_health_concern": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "upsert_medical_kb_document": Capability(writes=('db',), ddl=True,),  # backend/HealthAdvisor/mcpserver/knowledge_tool.py:840
    "delete_medical_kb_document": Capability(writes=('db',), ddl=True,),  # backend/HealthAdvisor/mcpserver/knowledge_tool.py:863
    "list_medical_kb_documents": Capability(ddl=True,),  # backend/HealthAdvisor/mcpserver/knowledge_tool.py:897  ← 只读动词，但实测 DDL
    "analyze_health_trends_async": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "extract_medical_info": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "extract_prescription_info": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "open_health_record": Capability(writes=('ui',), ui_actions=('navigateTo', 'openRecord'), ui_content_from_llm=True,),  # backend/HealthRecordsManager/mcpserver/page_control_tool.py:215
    "draft_health_record": Capability(writes=('ui',), ui_actions=('navigateTo', 'fillForm'), ui_content_from_llm=True,),  # backend/HealthRecordsManager/mcpserver/page_control_tool.py:401
    "add_medication_reminder": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/reminder_tool.py:57
    "get_medication_reminders": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "mark_reminder_taken": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/reminder_tool.py:250
    "add_health_reminder": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/reminder_tool.py:369
    "get_health_reminders": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "complete_reminder": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/reminder_tool.py:475
    "delete_reminder": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/reminder_tool.py:529
    "save_health_record": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/storage_tool.py:67
    "get_health_records": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_health_record_detail": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "save_medication": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/storage_tool.py:243
    "get_medications": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "delete_health_record": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/storage_tool.py:338
    "create_user_profile": Capability(writes=('db',),),  # backend/HealthRecordsManager/mcpserver/storage_tool.py:379
    "check_drug_interaction": Capability(egress=('agent',),),  # backend/MedicationReminder/mcpserver/drug_safety_tool.py:225
    "send_medication_notification": Capability(mock=True,),  # ⚠️ TODO 人工确认：mock，声明它「将来」会做什么（注释里写了「模拟发送通知」）
    "send_appointment_notification": Capability(mock=True,),  # ⚠️ TODO 人工确认：**无注释标记**，靠名字×AST 差集发现
    "check_overdue_medications": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "generate_daily_summary": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "set_notification_preferences": Capability(mock=True,),  # ⚠️ TODO 人工确认：mock，声明它「将来」会做什么（注释里写了「模拟保存通知偏好」）
    "add_medication_reminder": Capability(writes=('db',),),  # backend/MedicationReminder/mcpserver/reminder_tool.py:240
    "get_medication_reminders": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_today_reminders": Capability(writes=('ui',), ui_actions=('setData',),),  # backend/MedicationReminder/mcpserver/reminder_tool.py:485
    "log_medication_taken": Capability(writes=('db',),),  # backend/MedicationReminder/mcpserver/reminder_tool.py:606
    "add_appointment_reminder": Capability(writes=('db',),),  # backend/MedicationReminder/mcpserver/reminder_tool.py:721
    "get_upcoming_appointments": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "analyze_health_trends": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "generate_health_insights": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "detect_health_alerts": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_health_records_by_range": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_visit_summaries_by_range": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_visit_summaries_count_by_range": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_visit_summary_detail": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "save_generated_summary": Capability(writes=('db',),),  # backend/VisitSummaryGenerator/mcpserver/database_tool.py:220
    "get_health_record_detail": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "parse_medical_document": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "generate_visit_summary": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "get_sample_document": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "extract_text_from_image": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "validate_medical_document": Capability(),  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）
    "refresh_current_page": Capability(writes=('ui',), ui_actions=('refresh',),),  # backend/PhaCore/mcpserver/shared_page_control.py:148
    "show_page_alert": Capability(writes=('ui',), ui_actions=('showAlert',), ui_content_from_llm=True,),  # backend/PhaCore/mcpserver/shared_page_control.py:163  ← display 档：任意文本进用户视野
    "highlight_agent_card": Capability(writes=('ui',), ui_actions=('navigateTo', 'highlightAgent'), ui_content_from_llm=True,),  # backend/PhaCore/mcpserver/shared_page_control.py:181
    "ask_agent_in_page": Capability(writes=('ui',), ui_actions=('navigateTo', 'askAgent'), ui_content_from_llm=True,),  # backend/PhaCore/mcpserver/shared_page_control.py:201  ← delegate 档：前端替模型发起 agent 调用
    "filter_health_records": Capability(writes=('ui',), ui_actions=('navigateTo', 'setFilter'), ui_content_from_llm=True,),  # backend/PhaCore/mcpserver/shared_page_control.py:227
    "set_health_records_search": Capability(writes=('ui',), ui_actions=('navigateTo', 'setSearch'), ui_content_from_llm=True,),  # backend/PhaCore/mcpserver/shared_page_control.py:255
    "switch_medication_view": Capability(writes=('ui',), ui_actions=('navigateTo', 'setView'), ui_content_from_llm=True,),  # backend/PhaCore/mcpserver/shared_page_control.py:281
}
