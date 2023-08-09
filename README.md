# Variance Prediction of Mockingjay Reuse Distance Predictor - Implementing LLC Replacement Policy using ChampSim Simulator

Mockingjay Cache Replacement policy directly mimics Belady’s MIN Policy in a simple and effective way. Mockingjay uses a PC Based Predictor to learn each cache line’s reuse distance and evicts lines 
based on their predicted time of reuse. 

Here, we explore multiple methods to determine the accuracy of/variance in the Reuse Distance Predictor(RDP) - and inject them into the eviction algorithm. 
The Eviction algorithm is modified to have a higher tolerance for RDPs(believe less) of PCs having higher variance/lower accuracy. When conflicted between choosing the victim cache line 
(because of lower accuracy), the eviction policy chooses the cache line that has been least recently used.

The following benchmark traces have to be used: 
1. astar
2. bwaves
3. bzip2
4. cactusADM
5. calculix
6. gcc
7. GemsFDTD
8. lbm
9. leslie3d
10. libquantum

The cache is warmed for 200 million instructions and the behavior is measured for the next 1 billion instructions in Champsim simulator[https://github.com/ChampSim/ChampSim]

Refer to `Cache Replacement Policy.pdf` for more details
