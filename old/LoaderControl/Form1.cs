using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using JRPC_Client;
using XDevkit;

namespace LoaderControl
{
    public partial class Form1 : Form
    {
        IXboxConsole Jtag;

        public uint EndLib = new uint();
        public static uint StartLib = new uint();
        public static uint RestartLib = new uint();
        public static uint Shadowboot = new uint();
        public static uint LoadBin = new uint();

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (Jtag.Connect(out Jtag))
            {
                button1.Text = "Re-Connect";
                EndLib = Jtag.ResolveFunction("Loader.xex", 3);
                StartLib = Jtag.ResolveFunction("Loader.xex", 2);
                RestartLib = Jtag.ResolveFunction("Loader.xex", 4);
                Shadowboot = Jtag.ResolveFunction("Loader.xex", 5);
                LoadBin = Jtag.ResolveFunction("Loader.xex", 6);
            }
            
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Jtag.CallVoid(StartLib);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            Jtag.CallVoid(EndLib);
        }

        private void button4_Click(object sender, EventArgs e)
        {
            Jtag.CallVoid(RestartLib);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            Jtag.CallVoid(Shadowboot);
        }

        private void button6_Click(object sender, EventArgs e)
        {
            Jtag.CallVoid(LoadBin);
        }
    }
}
