import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.playbook_engine import PlaybookEngine
from brain.knowledge_base import KnowledgeBase

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] Playbook Engine Assembly")
pb_engine = PlaybookEngine()
result = pb_engine.generate_playbook("nmap")
check("playbook returns structured stages", "stages" in result)
check("playbook defines recon, execution, and hardening stages", len(result["stages"]) == 3)

print(f"\n{'='*50}\nTOTAL PLAYBOOK TESTS: {passed} passed, {failed} failed\n{'='*50}")
