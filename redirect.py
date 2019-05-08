from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IExtensionHelpers
from burp import IResponseInfo
from burp import IHttpService
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
        callbacks.setExtensionName("Get the host")
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

        # throw an exception that will appear in our error stream
        # exception assert
        # raise RuntimeException("Hello exception")
# IHttpListener
    #        * @param toolFlag A flag indicating the Burp tool that issued the request.
    #  * Burp tool flags are defined in the
    #  * <code>IBurpExtenderCallbacks</code> interface.
    #  * @param messageIsRequest Flags whether the method is being invoked for a
    #  * request or response.
    #  * @param messageInfo Details of the request / response to be processed.
    #  * Extensions can call the setter methods on this object to update the
    #  * current message and so modify Burp's behavior.
    #  */
    # void processHttpMessage(int toolFlag,
    #         boolean messageIsRequest,
    #         IHttpRequestResponse messageInfo);

# IResponseInfo

    #    */
    # List<String> getHeaders();

    # /**
    #  * This method is used to obtain the offset within the response where the
    #  * message body begins.
    #  *
    #  * @return The offset within the response where the message body begins.
    #  */
    # int getBodyOffset();

    # /**
    #  * This method is used to obtain the HTTP status code contained in the
    #  * response.
    #  *
    #  * @return The HTTP status code contained in the response.
    #  */
    # short getStatusCode();

    # /**
    #  * This method is used to obtain details of the HTTP cookies set in the
    #  * response.
    #  *
    #  * @return A list of <code>ICookie</code> objects representing the cookies
    #  * set in the response, if any.
    #  */
    # List<ICookie> getCookies();

    # /**
    #  * This method is used to obtain the MIME type of the response, as stated in
    #  * the HTTP headers.
    #  *
    #  * @return A textual label for the stated MIME type, or an empty String if
    #  * this is not known or recognized. The possible labels are the same as
    #  * those used in the main Burp UI.
    #  */
    # String getStatedMimeType();

    # /**
    #  * This method is used to obtain the MIME type of the response, as inferred
    #  * from the contents of the HTTP message body.
    #  *
    #  * @return A textual label for the inferred MIME type, or an empty String if
    #  * this is not known or recognized. The possible labels are the same as
    #  * those used in the main Burp UI.
    #  */
    # String getInferredMimeType();


# IHttpRequestResponse

    # * @return The request message.
    #  */
    # byte[] getRequest();

    # /**
    #  * This method is used to update the request message.
    #  *
    #  * @param message The new request message.
    #  */
    # void setRequest(byte[] message);

    # /**
    #  * This method is used to retrieve the response message.
    #  *
    #  * @return The response message.
    #  */
    # byte[] getResponse();

    # /**
    #  * This method is used to update the response message.
    #  *
    #  * @param message The new response message.
    #  */
    # void setResponse(byte[] message);

    # /**
    #  * This method is used to retrieve the user-annotated comment for this item,
    #  * if applicable.
    #  *
    #  * @return The user-annotated comment for this item, or null if none is set.
    #  */
    # String getComment();

    # /**
    #  * This method is used to update the user-annotated comment for this item.
    #  *
    #  * @param comment The comment to be assigned to this item.
    #  */
    # void setComment(String comment);

    # /**
    #  * This method is used to retrieve the user-annotated highlight for this
    #  * item, if applicable.
    #  *
    #  * @return The user-annotated highlight for this item, or null if none is
    #  * set.
    #  */
    # String getHighlight();

    # /**
    #  * This method is used to update the user-annotated highlight for this item.
    #  *
    #  * @param color The highlight color to be assigned to this item. Accepted
    #  * values are: red, orange, yellow, green, cyan, blue, pink, magenta, gray,
    #  * or a null String to clear any existing highlight.
    #  */
    # void setHighlight(String color);

    # /**
    #  * This method is used to retrieve the HTTP service for this request /
    #  * response.
    #  *
    #  * @return An
    #  * <code>IHttpService</code> object containing details of the HTTP service.
    #  */
    # IHttpService getHttpService();

    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):
        if toolFlag==4:
            # only handle response
            if messageIsRequest:
                response=messageInfo.getHttpService()
                # analyseresponse= self._helpers.analyzeResponse(response)
                print("get response")
                if response.getPort()==80:
                    messageInfo.setHttpService(self._helpers.buildHttpService("www.baidu.com",80,response.getProtocol()))
                    print(messageInfo.getHttpService().getHost())

                
                print"Protocol:",response.getProtocol()
                # if response.getHost()=="":
                #     do something
