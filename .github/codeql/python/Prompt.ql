/**
 * @name AI Prompt Usage
 * @description AI Prompt Usage
 * @kind problem
 * @problem.severity error
 * @security-severity 2.0
 * @sub-severity medium
 * @precision medium
 * @id githubsecuritylab/prompt-usage
 * @tags security
 */

import python
private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow

class AzureOpenAIClient extends DataFlow::Node  {
  AzureOpenAIClient() {
    this =
      API::moduleImport("openai")
          .getMember(["BaseAzureClient", "AzureOpenAI", "AsyncAzureOpenAI"])
          .getASubclass*()
          .getReturn()
          .getMember("chat")
          .getMember("completions")
          .getMember("with_raw_response")
          .getMember("create")
          .getACall()
  }
}

from AzureOpenAIClient sinks
select sinks, "AI prompt used"
