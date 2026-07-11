class WorkflowEngine:

    @staticmethod
    async def execute(workflow):
        """
        Executes a workflow callable.
        Future: logging, retry, metrics, event queue.
        """
        return await workflow()
