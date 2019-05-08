from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IExtensionHelpers
from burp import IResponseInfo
from java.io import PrintWriter
from java.lang import RuntimeException



# public static final int TOOL_COMPARER   512
# public static final int TOOL_DECODER    256
# public static final int TOOL_EXTENDER   1024
# public static final int TOOL_INTRUDER   32
# public static final int TOOL_PROXY  4
# public static final int TOOL_REPEATER   64
# public static final int TOOL_SCANNER    16
# public static final int TOOL_SEQUENCER  128
# public static final int TOOL_SPIDER 8
# public static final int TOOL_SUITE  1
# public static final int TOOL_TARGET 2

class BurpExtender(IBurpExtender,IHttpListener):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("My first burp extension")
        self._helpers = callbacks.getHelpers()
        
        

        # obtain our output and error streams
     
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        
        callbacks.registerHttpListener(self)
        

        # write a message to our output stream
        stdout.println("Hello output")

        # write a message to our error stream
        # stderr.println("Hello errors")

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Hello alerts")


    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):
        if toolFlag==4:
            # only handle response
            if not messageIsRequest:
                response=messageInfo.getResponse()
                analyseresponse= self._helpers.analyzeResponse(response)
                print("get response")
                print(analyseresponse.getHeaders()[0])
                print(response[analyseresponse.getBodyOffset():].tostring())
                # if response[analyseresponse.getBodyOffset():].tostring()=="":
                #     do something
