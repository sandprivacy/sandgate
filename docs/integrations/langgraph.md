# sandgate + LangGraph

LangGraph agents load MCP tools through the official adapters package.
sandgate is a plain stdio MCP server, so the wiring is the standard
pattern:

```bash
pip install langchain-mcp-adapters langgraph
npm install -g @sandprivacy/sandgate   # plus: sandgate init && sandgate pair <relay>
```

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "sandgate": {
        "transport": "stdio",
        "command": "sandgate",
        "args": ["serve"],
        "env": {"SANDGATE_PASSPHRASE": "your-passphrase"},
    }
})

tools = await client.get_tools()
agent = create_react_agent("anthropic:claude-sonnet-5", tools)

result = await agent.ainvoke({
    "messages": "Before wiring the refund, request my approval via sandgate."
})
```

(Check the adapters package docs for the exact API of the version you
install — the shape above is the documented pattern at time of writing.)

Notes:
- LangGraph's own `interrupt()` pauses a graph for in-process input;
  sandgate complements it with out-of-band humans — a phone that buzzes
  wherever you are, 2FA codes from an encrypted vault, email
  verification. Use both: interrupts for workflow decisions, sandgate
  for secrets and away-from-keyboard approvals.
- `ask_human` returns free text — SMS codes received on your real
  number, security questions, choices.
