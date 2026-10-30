# التعلم الخارجي المحكوم

تُعامل إجابات OpenAI وGemini في AI AYFAM كأدلة مرشحة، وليست حقائق موثوقة تلقائياً.

## ما الذي يُحفظ؟

عند نجاح رد المزود الخارجي، تُحفظ في قاعدة SQLite المحلية:

- المزود والنموذج والمصدر.
- السؤال المرسل والسياق التشغيلي المختصر.
- الإجابة كاملة.
- تقييم فحص أولي قابل للتفسير، يتضمن درجة تقريبية، علامات التحذير، وبصمة الإجابة.

تُنشأ تلقائياً مسودة معرفة في جدول `learning_proposals`، ولا تُكتب الإجابة مباشرة في جدول `knowledge`.

## دورة الموافقة

1. `proposed`: اقتراح معزول ينتظر مراجعة بشرية.
2. `reviewed`: تمت الموافقة البشرية مع ملاحظة مراجعة إلزامية.
3. `tested`: سُجلت نتيجة اختبار آلي ناجحة. مدير الحوكمة لا ينفذ أوامر الاختبار؛ يسجل نتيجة الاختبار التي شغلها خط CI أو المشغّل الموثوق.
4. `applied`: تُستخدم هذه الحالة للمعرفة فقط بعد تحقق الشرطين السابقين.
5. اقتراحات الكود تنتقل بعد الاختبار إلى `ready_for_merge` فقط. لا يعدّل مدير التعلم أي ملف ولا ينفذ patch تلقائياً؛ يجب تطبيق التغيير في فرع منفصل ثم مراجعته ودمجه عبر Git بعد نجاح CI.

## واجهة Python

```python
from brain.learning_governance import LearningGovernance

governance = LearningGovernance(agent.kb)

# اقتراح معرفة جديد
proposal_id = governance.create_knowledge_proposal(
    title="...", description="...", content="...",
    category="...", key="..."
)

governance.review(proposal_id, approved=True, note="تمت مراجعة المصدر والدليل")
governance.record_test_result(
    proposal_id, passed=True, command="pytest -q", output="..."
)
governance.apply(proposal_id)
```

لا توجد دالة تسمح بتطبيق اقتراح كود؛ `apply()` يحوله إلى `ready_for_merge` فقط. وهذا مقصود لمنع التطوير الذاتي العشوائي أو تنفيذ تعليمات قد تكون ضارة داخل إجابة مزود خارجي.
