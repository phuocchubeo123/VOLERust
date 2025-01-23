use crate::prg::PRG;

// No multithreading
pub struct MpfssReg {
    party: usize,
    item_n: usize,
    idx_max: usize, 
    m: usize,
    tree_height: usize,
    leave_n: usize,
    tree_n: usize,
    is_malicious: bool,
    prg: PRG,
    ggm_tree: Vec<Vec<FE>>,
    check_chialpha_buf: Vec<FE>,
}

impl MpfssReg {
    pub fn new(party: usize, n: usize, t: usize, log_bin_sz: usize) -> Self {
        // make sure n = t * leave_n
        Self {
            party: party,
            item_n: t,
            idx_max: n,
            m: 0,
            tree_height: log_bin_sz + 1,
            leave_n: 1 << log_bin_sz,
            tree_n: item_n,
            is_malicious: false,
            ggm_tree: Vec![[FE::zero();t]; 1 << log_bin_sz],
            check_chialpha_buf: Vec![FE::zero(); t],
            check_vw_buf: Vec![FE::zero(); t]
        }
    }
}