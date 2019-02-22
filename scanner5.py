import PyQt5.QtWidgets as qw
import PyQt5.QtGui as qg
from PyQt5.QtCore import (
    Qt, 
    QSize,
    QThread,
    pyqtSignal
)
import math
import sys
import socket
import threading
from ipaddress import ip_network
from queue import Queue, Empty
import time


class Scanner(QThread):
    signal = pyqtSignal('QString')
    finished = pyqtSignal()
    progress = pyqtSignal('QString')

    def __init__(self, q):
        """
        Parameters
        ----------
        q: list
            list of (host, port)
        """
        QThread.__init__(self)
        self.theQueue = q



    def __del__(self):
        self.wait()

    def run(self):
        while True:
            if len(self.theQueue) == 0:
                return
            host, port = self.theQueue.pop(0)
            if host == 'last':
                self.finished.emit()
                return
            if port == -1:
                progress_str = 'Scannning {}'.format(host)
                print(progress_str)
                self.progress.emit(progress_str)
                return
            is_open = False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            try:
                err = sock.connect_ex((host, port))
            except (socket.error, socket.timeout):
                is_open = False
            else:
                if err:
                    is_open = False
                else:
                    is_open = True
            
            if is_open:
                result = '{}:{}'.format(host, port)
                print(result, 'open')
                self.signal.emit(result)

def layoutCenter(*items):
    box = qw.QHBoxLayout()
    box.addStretch(1)
    for item in items:
        box.addWidget(item)
    box.addStretch(1)
    return box

class QtGui(qw.QWidget):
    def __init__(self):
        super().__init__()

        self.pagiCur = None
        self.totalPage = 0
        self.perPage = 8
        self.ports = []
        self.inputs = {}
        self.results_ = []
        self.threads = []
        self.hosts = []
        self.port_range = range(0)
        self.status = {}
        self.beginTime = 0

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Port Scanner')
        self.setStyleSheet("background-color: white")
        self.setWindowIcon(qg.QIcon('img/scan.png'))

        width = 1200
        height = width / 1.618
        self.setGeometry(300, 90, width, height)
        qtRectangle = self.frameGeometry()
        centerPoint = qw.QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        vbox = qw.QVBoxLayout()
        hhbox = qw.QHBoxLayout()

        lTitle = qw.QLabel("Control Panel")
        lTitleHbox = layoutCenter(lTitle)

        rTitle = qw.QLabel("Open Ports")
        rTitleHbox = layoutCenter(rTitle)

        titleFont = qg.QFont('Maiandra GD', 40, 15)

        for title in [lTitle, rTitle]:
            title.setStyleSheet('color: #333')
            title.setFont(titleFont)

        lVbox = qw.QVBoxLayout()
        lVbox.addLayout(lTitleHbox)
        lVbox.addStretch(4)

        self.inputs = {
            'IP address': {},
            'Min port #': {},
            'Max port #': {}
        }

        labelFont = qg.QFont('Anonymice Powerline', 25)

        for key in self.inputs:
            in_ = self.inputs[key]
            in_['label'] = qw.QLabel(key)
            in_['edit'] = qw.QLineEdit()
            in_['box'] = layoutCenter(in_['label'], in_['edit'])

            in_['label'].setFont(labelFont)
            in_['label'].setStyleSheet('color: #333')
            in_['edit'].setStyleSheet('''
                color: #333;
                font-size: 22px;
                padding: 5px 8px;
                margin-left: 15px;
            ''')

            lVbox.addLayout(in_['box'])
            lVbox.addStretch(1)

        self.inputs['IP address']['edit'].setText('127.0.0.1')
        self.inputs['Min port #']['edit'].setText('1')
        self.inputs['Max port #']['edit'].setText('10000')

        lVbox.addStretch(4)

        lBegin = qw.QPushButton("Begin Scanning")
        lBeginHbox = layoutCenter(lBegin)
        lBegin.clicked.connect(self.handleBegin)

        lStop = qw.QPushButton("Stop Scanning")
        lStopHbox = layoutCenter(lStop)
        lStop.clicked.connect(self.handleStop)

        for btn in [lBegin, lStop]:
            btn.setStyleSheet('''
                QPushButton {
                    border: none;
                    padding: 12px 18px;
                    font-family: Maiandra GD;
                    font-size: 35px;
                    color: white;
                    background-color: #33adff;
                    width: 230px;
                }
                QPushButton:hover {
                    background-color: #1aa3ff;
                }
            ''')
            btn.setCursor(qg.QCursor(Qt.PointingHandCursor))


        lVbox.addLayout(lBeginHbox)
        lVbox.addStretch(1)
        lVbox.addLayout(lStopHbox)
        lVbox.addStretch(2)

        rVbox = qw.QVBoxLayout()
        rVbox.addLayout(rTitleHbox)
        rVbox.addStretch(7)

        for i in range(self.perPage):
            port = {}
            port['label'] = qw.QLabel('')
            port['label'].setFont(labelFont)
            port['label'].setStyleSheet('color: #333; font-size: 30px')
            port['box'] = layoutCenter(port['label'])

            rVbox.addLayout(port['box'])
            rVbox.addStretch(1)

            self.ports.append(port)

        rVbox.addStretch(7)

        pagiLeft = qw.QPushButton()
        pagiLeft.setIcon(qg.QIcon("img/paging.png"))
        pagiLeft.clicked.connect(self.handleLeftPagi)
        self.pagiCur = qw.QLabel('0/0')
        self.pagiCur.setFont(labelFont)
        self.pagiCur.setStyleSheet('''
            color: #333; 
            font-size: 36px;
            margin: 10px 20px;
        ''')
        pagiRight = qw.QPushButton()
        pagiRight.setIcon(qg.QIcon("img/paging2.png"))
        pagiRight.clicked.connect(self.handleRightPagi)

        for pagi in [pagiLeft, pagiRight]:
            pagi.setIconSize(QSize(48,48))
            pagi.setCursor(qg.QCursor(Qt.PointingHandCursor))
            pagi.setStyleSheet('border: none')

        rpbox = layoutCenter(pagiLeft, self.pagiCur, pagiRight)
        rVbox.addLayout(rpbox)
        rVbox.addStretch(7)

        mSeperator = qw.QPushButton('')
        mSeperator.setStyleSheet('''
            width: 0;
            height: 500px;
            border-left: 2px solid #f3f3f3;
            border-right: 2px solid #f3f3f3;
            border-top: none;
            border-bottom: none;
        ''')
        mVbox = layoutCenter(mSeperator)

        hhbox.addLayout(lVbox, 20)
        hhbox.addLayout(mVbox, 1)
        hhbox.addLayout(rVbox, 20)

        self.status = {
            'icon': qw.QLabel(),
            'label': qw.QLabel()
        }
        self.status['icon'].setPixmap(qg.QPixmap("img/blank.png"))
        self.status['label'].setStyleSheet('''
            color: #666;
            font-size: 32px;
        ''')
        statusHbox = layoutCenter(self.status['icon'], self.status['label'])

        vbox.addStretch(1)
        vbox.addLayout(hhbox, 18)
        vbox.addLayout(statusHbox, 1)
        vbox.addStretch(1)
        self.setLayout(vbox)
        self.show()

    def notice(self, icon='blank', msg=''):
        self.status['icon'].setPixmap(qg.QPixmap("img/%s.png" % icon))
        self.status['label'].setText(msg)

    def handleBegin(self):
        self.beginTime = time.time()
        self.notice()
        self.totalPage = 0
        self.results_ = []
        self.threads = []
        self.clearPortList()
        self.pagiCur.setText('0/0')

        target = self.inputs['IP address']['edit'].text()
        try:
            port_minmax = (
                int(self.inputs['Min port #']['edit'].text()),
                int(self.inputs['Max port #']['edit'].text())
            )
        except ValueError:
            return

        self.port_range = range(*port_minmax)
        if not (0 <= port_minmax[0] <= 65535 and 0 <= port_minmax[1] <= 65535):
            self.notice('wrong', 'Port must be 0-65535')
            return

        try:
            self.hosts = [socket.gethostbyname(target)]
        except socket.gaierror:
            try:
                self.hosts = [str(host) for host in ip_network(target)]
            except ValueError:
                self.notice('wrong', 'Invalid ip address')
                return

        self.theQueue = []
        for host in self.hosts:
            self.theQueue.append((host, -1))
            for port in self.port_range:
                self.theQueue.append((host, port))
                if self.hosts[-1] == host and self.port_range[-1] == port:
                    self.theQueue.append(('last', 'last'))

        for i in range(1300):
            t = Scanner(self.theQueue)
            t.signal.connect(self.appendNew)
            t.finished.connect(self.handleFinished)
            t.progress.connect(self.handleProgress)
            self.threads.append(t)
            t.start()


    def handleFinished(self):
        duration = time.time() - self.beginTime
        self.notice('check', 'Done in {:.1f}s'.format(duration))

    def handleProgress(self, progress_str):
        self.notice('loader', progress_str)

    def handleStop(self):
        self.theQueue.clear()
        self.notice()

    def clearPortList(self):
        for port in self.ports:
            port['label'].setText('')

    def setPage(self, page):
        assert 1 <= page <= self.totalPage
        self.pagiCur.setText('{}/{}'.format(page, self.totalPage))
        pageContent = self.results_[self.perPage*(page-1):self.perPage*page]

        self.clearPortList()
        for i, result in enumerate(pageContent):
            self.ports[i]['label'].setText(result)

    def handleLeftPagi(self):
        text = self.pagiCur.text()
        curPage = int(text.split('/')[0])
        if curPage <= 1:
            return
        self.setPage(curPage - 1)

    def handleRightPagi(self):
        text = self.pagiCur.text()
        curPage = int(text.split('/')[0])
        if curPage >= self.totalPage:
            return
        self.setPage(curPage + 1)

    def appendNew(self, result):
        self.totalPage = math.ceil(len(self.results_) / self.perPage)
        appendIndex = len(self.results_) % self.perPage
        text = self.pagiCur.text()
        a, b = text.split('/')
        a, b = int(a), int(b)

        def setPage_(a, b):
            self.pagiCur.setText('{}/{}'.format(a, b))

        if a == b and appendIndex == 0:
            self.clearPortList()
            setPage_(a + 1, b + 1)

        if a == b:
            self.ports[appendIndex]['label'].setText(result)

        if a != b and appendIndex == 0:
            setPage_(a, b + 1)

        self.results_.append(result)


if __name__ == '__main__':
    app = qw.QApplication(sys.argv)
    gui = QtGui()
    app.exec_()
