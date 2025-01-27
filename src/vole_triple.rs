use crate::preot::OTPre;
use crate::comm_channel::CommunicationChannel;
use crate::base_cot::BaseCot;
use crate::lpn::Lpn;
use crate::mpfss_reg::MpfssReg;
use crate::base_svole::BaseSvole;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct PrimalLPNParameterFp61 {
    n: usize,
    t: usize,
    k: usize,
    log_bin_sz: usize,
    n_pre: usize,
    t_pre: usize,
    k_pre: usize,
    log_bin_sz_pre: usize,
    n_pre0: usize,
    t_pre0: usize,
    k_pre0: usize,
    log_bin_sz_pre0: usize,
}

impl PrimalLPNParameterFp61 {
    // Default constructor
    pub fn new() -> Self {
        Self {
            n: 0,
            t: 0,
            k: 0,
            log_bin_sz: 0,
            n_pre: 0,
            t_pre: 0,
            k_pre: 0,
            log_bin_sz_pre: 0,
            n_pre0: 0,
            t_pre0: 0,
            k_pre0: 0,
            log_bin_sz_pre0: 0,
        }
    }

    // Parameterized constructor
    pub fn with_params(
        n: usize,
        t: usize,
        k: usize,
        log_bin_sz: usize,
        n_pre: usize,
        t_pre: usize,
        k_pre: usize,
        log_bin_sz_pre: usize,
        n_pre0: usize,
        t_pre0: usize,
        k_pre0: usize,
        log_bin_sz_pre0: usize,
    ) -> Self {
        // Ensure parameters are valid
        if n != t * (1 << log_bin_sz)
            || n_pre != t_pre * (1 << log_bin_sz_pre)
            || n_pre < k + t + 1
        {
            panic!("LPN parameter not matched");
        }

        Self {
            n,
            t,
            k,
            log_bin_sz,
            n_pre,
            t_pre,
            k_pre,
            log_bin_sz_pre,
            n_pre0,
            t_pre0,
            k_pre0,
            log_bin_sz_pre0,
        }
    }

    // Compute buffer size
    pub fn buf_sz(&self) -> usize {
        self.n - self.t - self.k - 1
    }
}

// Default instance
pub const FP_DEFAULT: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 10168320,
    t: 4965,
    k: 158000,
    log_bin_sz: 11,
    n_pre: 166400,
    t_pre: 2600,
    k_pre: 5060,
    log_bin_sz_pre: 6,
    n_pre0: 9600,
    t_pre0: 600,
    k_pre0: 1220,
    log_bin_sz_pre0: 4,
};


pub struct VoleTriple {
    party: usize,
    param: PrimalLPNParameterFp61,
    m: usize,
    ot_used: usize,
    ot_limit: usize,
    is_malicious: bool,
    extend_initialized: bool,
    pre_ot_inplace: bool,

    pre_y: Vec<FE>,
    pre_z: Vec<FE>,
    pre_x: Vec<FE>,
    vole_y: Vec<FE>,
    vole_z: Vec<FE>,
    vole_x: Vec<FE>,

    cot: BaseCot,
    pre_ot: Option<OTPre>,

    delta: FE,
    mpfss: Option<MpfssReg>,
}

impl VoleTriple {
    pub fn new<IO: CommunicationChannel>(party: usize, malicious: bool, io: &mut IO, param: PrimalLPNParameterFp61) -> Self {
        let n_pre = param.n_pre;
        let t_pre = param.t_pre;
        let n = param.n;
        let t = param.t;
        let mut cot = BaseCot::new(party, malicious);
        cot.cot_gen_pre(io, None);

        VoleTriple {
            party: party,
            param: param,
            m: 0,
            ot_used: 0,
            ot_limit: 0,
            is_malicious: malicious,
            extend_initialized: false,
            pre_ot_inplace: false,

            pre_y: vec![FE::zero(); n_pre],
            pre_z: vec![FE::zero(); n_pre],
            pre_x: vec![FE::zero(); t_pre + 1],
            vole_y: vec![FE::zero(); n],
            vole_z: vec![FE::zero(); n],
            vole_x: vec![FE::zero(); t + 1],

            cot: cot,
            pre_ot: None,

            delta: FE::zero(),
            mpfss: None,
        }
    }

    pub fn extend_send<IO: CommunicationChannel>(&mut self, io: &mut IO, y: &mut [FE], mpfss: &mut MpfssReg, pre_ot: &mut OTPre, lpn: &mut Lpn, key: &[FE], t: usize) {
        mpfss.sender_init(self.delta);
        mpfss.mpfss_sender(io, pre_ot, key, y);
        // // y is already a regular vector (concat of n/t unit vectors), which corresponses to the noise in LPN
        lpn.compute_send(y, &key[t+1..]);
    }

    pub fn extend_recv<IO: CommunicationChannel>(&mut self, io: &mut IO, y: &mut [FE], z: &mut [FE], mpfss: &mut MpfssReg, pre_ot: &mut OTPre, lpn: &mut Lpn, mac: &[FE], u: &[FE], t: usize) {
        mpfss.receiver_init();
        mpfss.mpfss_receiver(io, pre_ot, mac, u, y, z);
        lpn.compute_recv(y, z, &mac[t+1..], &u[t+1..]);
    }

    pub fn setup_sender<IO: CommunicationChannel>(&mut self, io: &mut IO, delta: FE) {
        self.delta = delta;

        let seed_pre0 = [0u8; 16];
        let seed_field_pre0 = [[0u8; 16]; 4];
        let mut lpn_pre0 = Lpn::new(self.param.k_pre0, self.param.n_pre0, &seed_pre0, &seed_field_pre0);
        let mut mpfss_pre0 = MpfssReg::new(self.param.n_pre0, self.param.t_pre0, self.param.log_bin_sz_pre0, self.party);
        mpfss_pre0.set_malicious();
        let mut pre_ot_ini0 = OTPre::new(self.param.log_bin_sz_pre0, self.param.t_pre0);

        let m_pre0 = self.param.log_bin_sz_pre0 * self.param.t_pre0;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini0, m_pre0, None);

        // mac = key + delta * u
        let triple_n0 = 1 + self.param.t_pre0 + self.param.k_pre0;
        let mut key = vec![FE::zero(); triple_n0];
        let mut svole0 = BaseSvole::new_sender(io, self.delta);
        svole0.triple_gen_send(io, &mut key, triple_n0);

        io.flush();

        let mut pre_y0 = vec![FE::zero(); self.param.n_pre0];
        self.extend_send(io, &mut pre_y0, &mut mpfss_pre0, &mut pre_ot_ini0, &mut lpn_pre0, &key, self.param.t_pre0);


        let seed_pre = [0u8; 16];
        let seed_field_pre = [[0u8; 16]; 4];
        let mut lpn_pre = Lpn::new(self.param.k_pre, self.param.n_pre, &seed_pre, &seed_field_pre);
        let mut mpfss_pre = MpfssReg::new(self.param.n_pre, self.param.t_pre, self.param.log_bin_sz_pre, self.party); 
        mpfss_pre.set_malicious();
        let mut pre_ot_ini = OTPre::new(self.param.log_bin_sz_pre, self.param.t_pre);

        let m_pre = self.param.log_bin_sz_pre * self.param.t_pre;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini, m_pre, None);

        // 
        let triple_n = 1 + self.param.t_pre + self.param.k_pre;        
        let mut pre_y = vec![FE::zero(); self.param.n_pre];
        self.extend_send(io, &mut pre_y, &mut mpfss_pre, &mut pre_ot_ini, &mut lpn_pre, &pre_y0[..triple_n], self.param.t_pre);
        self.pre_y.copy_from_slice(&pre_y);

        self.pre_ot_inplace = true;
    }

    pub fn setup_receiver<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        let seed_pre0 = [0u8; 16];
        let seed_field_pre0 = [[0u8; 16]; 4];
        let mut lpn_pre0 = Lpn::new(self.param.k_pre0, self.param.n_pre0, &seed_pre0, &seed_field_pre0);
        let mut mpfss_pre0 = MpfssReg::new(self.param.n_pre0, self.param.t_pre0, self.param.log_bin_sz_pre0, self.party);
        mpfss_pre0.set_malicious();
        let mut pre_ot_ini0 = OTPre::new(self.param.log_bin_sz_pre0, self.param.t_pre0);

        let m_pre0 = self.param.log_bin_sz_pre0 * self.param.t_pre0;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini0, m_pre0, None);

        // mac = key + delta * u
        let triple_n0 = 1 + self.param.t_pre0 + self.param.k_pre0;
        let mut mac = vec![FE::zero(); triple_n0];
        let mut u = vec![FE::zero(); triple_n0];
        let mut svole0 = BaseSvole::new_receiver(io);
        svole0.triple_gen_recv(io, &mut mac, &mut u, triple_n0);

        io.flush();

        let mut pre_y0 = vec![FE::zero(); self.param.n_pre0];
        let mut pre_z0 = vec![FE::zero(); self.param.n_pre0];
        self.extend_recv(io, &mut pre_y0, &mut pre_z0, &mut mpfss_pre0, &mut pre_ot_ini0, &mut lpn_pre0, &mac, &u, self.param.t_pre0);

        let seed_pre = [0u8; 16];
        let seed_field_pre = [[0u8; 16]; 4];
        let mut lpn_pre = Lpn::new(self.param.k_pre, self.param.n_pre, &seed_pre, &seed_field_pre);
        let mut mpfss_pre = MpfssReg::new(self.param.n_pre, self.param.t_pre, self.param.log_bin_sz_pre, self.party); 
        mpfss_pre.set_malicious();
        let mut pre_ot_ini = OTPre::new(self.param.log_bin_sz_pre, self.param.t_pre);

        let m_pre = self.param.log_bin_sz_pre * self.param.t_pre;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini, m_pre, None);

        // 
        let triple_n = 1 + self.param.t_pre + self.param.k_pre;        
        let mut pre_y = vec![FE::zero(); self.param.n_pre];
        let mut pre_z = vec![FE::zero(); self.param.n_pre];
        self.extend_recv(io, &mut pre_y, &mut pre_z, &mut mpfss_pre, &mut pre_ot_ini, &mut lpn_pre, &pre_y0[..triple_n], &pre_z0[..triple_n], self.param.t_pre);
        self.pre_y.copy_from_slice(&pre_y);
        self.pre_z.copy_from_slice(&pre_z);

        self.pre_ot_inplace = true;
    }
}