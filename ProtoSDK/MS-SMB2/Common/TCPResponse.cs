using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2.Common
{
    public class TCPResponse
    {
        public FILEID fileId;

        public Smb2CreateContextResponse[] serverCreateContexts;

        public Packet_Header responseHeader;

        public CREATE_Response responsePayload;

        public uint status;
    }
}
