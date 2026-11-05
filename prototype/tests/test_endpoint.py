import copy
import socket
import threading
import unittest
from geneva_healthcheck import make_server,measure,diagnose,FILE_BYTES,REFERENCE_SHA256

class EndpointTests(unittest.TestCase):
    def probe_mode(self,mode='normal',timeout=2,delay=0):
        server=make_server(('127.0.0.1',0),mode,delay)
        thread=threading.Thread(target=server.serve_forever);thread.daemon=True;thread.start()
        try: return measure('127.0.0.1',server.server_port,'ultrasurf.example',timeout)
        finally: server.shutdown();server.server_close();thread.join()
    def test_full_http_file(self):
        r=self.probe_mode();o=r['observation']
        self.assertEqual(o['bytes_received'],FILE_BYTES)
        self.assertEqual(o['sha256'],REFERENCE_SHA256)
        self.assertTrue(r['diagnosis']['delivery_verified'])
    def test_truncated_body_is_not_success(self):
        r=self.probe_mode('truncate')
        self.assertEqual(r['observation']['bytes_received'],FILE_BYTES//2)
        self.assertEqual(r['diagnosis']['symptom'],'incomplete_or_wrong_length')
        self.assertEqual(r['diagnosis']['root_cause'],'undetermined')
    def test_equal_length_corruption_is_not_success(self):
        r=self.probe_mode('corrupt')
        self.assertEqual(r['observation']['bytes_received'],FILE_BYTES)
        self.assertEqual(r['diagnosis']['symptom'],'integrity_mismatch')
    def test_delayed_headers_timeout_not_censorship_claim(self):
        r=self.probe_mode('delay',timeout=.08,delay=.2)
        self.assertEqual(r['diagnosis']['symptom'],'transfer_timeout')
        self.assertEqual(r['diagnosis']['censorship_attribution'],'not_inferred')
    def test_http_status_is_not_success(self):
        r=self.probe_mode('status503')
        self.assertEqual(r['diagnosis']['symptom'],'http_status_failure')
        self.assertFalse(r['diagnosis']['delivery_verified'])
    def test_refused_connection(self):
        
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            r=measure('127.0.0.1',sock.getsockname()[1],timeout=1)
        self.assertEqual(r['diagnosis']['symptom'],'connection_refused')
    def test_censor_label_cannot_change_diagnosis(self):
        o=self.probe_mode()['observation'];expected=diagnose(o)
        for label in ['censor1','censor2','normal','truncate']:
            leaked=copy.deepcopy(o);leaked.update(censor=label,server_mode=label,strategy=label)
            self.assertEqual(diagnose(leaked),expected)
    def test_timeout_with_reset_like_text_is_not_reset_evidence(self):
        o=self.probe_mode()['observation'];o.update(error_kind='timeout',stage='body',error_message='RST censor1')
        self.assertEqual(diagnose(o)['symptom'],'transfer_timeout')

if __name__=='__main__': unittest.main(verbosity=2)
