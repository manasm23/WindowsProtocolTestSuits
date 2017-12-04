using Microsoft.Protocols.TestSuites.FileSharing.Common.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.TestSuite.Multiple
{
    [TestClass]
    public class Multiple : SMB2TestBase
    {
        #region Test Initialize and Cleanup
        [ClassInitialize()]
        public static void ClassInitialize(TestContext testContext)
        {
            Initialize(testContext);
        }

        [ClassCleanup()]
        public static void ClassCleanup()
        {
            Cleanup();
        }
        #endregion


        [TestMethod]
        [TestCategory(TestCategories.Multiple)]
        [Description("Send multiple Create requests to SUT and verify response")]
        public void Send_Multiple_Requests()
        {
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Initialize the test client.");
            Smb2FunctionalClient client = new Smb2FunctionalClient(TestConfig.Timeout, TestConfig, BaseTestSite);
            uint treeId;
            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to the SMB2 basic share by sending the following requests: NEGOTIATE; SESSION_SETUP; TREE_CONNECT.");
            ConnectToShare(client, out treeId);

            List<Smb2SinglePacket> requestPackets = new List<Smb2SinglePacket>();
            for (int i = 1; i <= 10; i++)
            {
                BaseTestSite.Log.Add(LogEntryKind.TestStep, "Construct the {0} Create packet.", i);
                string fileName = string.Format("FileNew_{0}_{1}.txt", i, Guid.NewGuid());
                
                Task<Smb2CreateRequestPacket> t1 = Task<Smb2CreateRequestPacket>.Factory.StartNew(() =>
                    ConstructCreatePacket(client.SessionId, treeId, fileName));

                requestPackets.Add(t1.Result);
            }

            client.EnableSessionSigningAndEncryption(enableSigning: testConfig.SendSignedRequest, enableEncryption: false);

            Task<List<ulong>> sendRequest =  Task<List<ulong>>.Factory.StartNew(() => client.SendCompoundPacket(requestPackets));            

            List<Smb2SinglePacket> responsePackets = client.ReceiveCompoundPacket(sendRequest.Result);

            BaseTestSite.Log.Add(LogEntryKind.TestStep, "Verify responses to the compounded request.");
            foreach (var responsePacket in responsePackets)
            {
                if (TestConfig.Platform == Platform.WindowsServer2016 && responsePacket.Header.Status != Smb2Status.STATUS_SUCCESS)
                {

                }
                else
                {
                    BaseTestSite.Assert.AreEqual(
                        Smb2Status.STATUS_SUCCESS,
                        responsePacket.Header.Status,
                        "{0} should succeed, actual status is {1}", responsePacket.Header.Command, Smb2Status.GetStatusCode(responsePacket.Header.Status));
                }
            }

            client.TreeDisconnect(treeId);
            client.LogOff();
            client.Disconnect();
        }

        private void ConnectToShare(Smb2FunctionalClient client, out uint treeId)
        {
            client.ConnectToServer(TestConfig.UnderlyingTransport, TestConfig.SutComputerName, TestConfig.SutIPAddress);
            client.Negotiate(
                TestConfig.RequestDialects,
                TestConfig.IsSMB1NegotiateEnabled,
                capabilityValue: Capabilities_Values.GLOBAL_CAP_ENCRYPTION); // To enable encryption later.
            client.SessionSetup(TestConfig.DefaultSecurityPackage, TestConfig.SutComputerName, TestConfig.AccountCredential, false);
            client.TreeConnect(Smb2Utility.GetUncPath(testConfig.SutComputerName, testConfig.BasicFileShare), out treeId);
        }

        /// <summary>
        /// Construct a Create packet which is the first or an unrelated packet in the chain
        /// </summary>
        private Smb2CreateRequestPacket ConstructCreatePacket(ulong sessionId, uint treeId, string fileName)
        {
            Smb2CreateRequestPacket createPacket = new Smb2CreateRequestPacket();
            createPacket.Header.Command = Smb2Command.CREATE;
            createPacket.Header.SessionId = sessionId;
            createPacket.Header.TreeId = treeId;
            createPacket.PayLoad.CreateDisposition = CreateDisposition_Values.FILE_OPEN_IF;
            createPacket.PayLoad.CreateOptions = CreateOptions_Values.FILE_NON_DIRECTORY_FILE;
            createPacket.PayLoad.ImpersonationLevel = ImpersonationLevel_Values.Impersonation;
            createPacket.PayLoad.DesiredAccess = AccessMask.GENERIC_READ | AccessMask.GENERIC_WRITE | AccessMask.DELETE;
            createPacket.PayLoad.ShareAccess = ShareAccess_Values.FILE_SHARE_READ | ShareAccess_Values.FILE_SHARE_WRITE | ShareAccess_Values.FILE_SHARE_DELETE;
            byte[] nameBuffer = Encoding.Unicode.GetBytes(fileName);
            createPacket.PayLoad.NameOffset = createPacket.BufferOffset;
            createPacket.PayLoad.NameLength = (ushort)nameBuffer.Length;
            createPacket.Buffer = nameBuffer;
            return createPacket;
        }
    }
}
