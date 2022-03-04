// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "./IBank.sol";

contract Bank is Ownable, ReentrancyGuard {
    address constant _trustedForwarder =
        0x5B38Da6a701c568545dCfcB03FcB875f56beddC4; 

    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Info of each user.
    struct UserInfo {
        uint256 amount; // Cuántos tokens ha proporcionado el usuario.
        uint256 rewardDebt; // Recompensa de deuda.
        uint256 rewardLockedUp; // Intereses bloqueados.
        uint256 nextHarvestUntil; // Cuándo puede volver a cosechar el usuario.
        uint256 lastInteraction; // Última vez que el usuario depositó o reclamó recompensas, renovando el deposito
    }

    
    struct PoolInfo {
        IERC20 token; // Direccion de Eth        
        uint256 lastRewardBlock; // Número del último bloque en el que se produce la distribución de Eth.
        uint256 accEthPerShare; // Eth acumulado por accion.
        uint16 depositFeeBP; // Comision por puntos basicos
        uint256 harvestInterval; // intervalos para retiros
        uint256 totalTokens; // Tokens totales
    }

    IBank public eth;

    // El operador solo puede actualizar EmissionRate y AllocPoint para proteger los tokenomics
    address private _operator;

    // Dev address.
    address public devAddress;

    // Deposit Fee address
    address public feeAddress;

    // eth tokens created per block
    uint256 public ethPerBlock;

    // intervalo maximo para retirar: 14 days
    uint256 public constant MAXIMUM_HARVEST_INTERVAL = 14 days;

    // maximo fee de deposito: 3%
    uint16 public constant MAXIMUM_DEPOSIT_FEE_RATE = 300;

    
    PoolInfo[] public poolInfo;

    // Informacion de cada usuario que deposita.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;

    // 
    uint256 public totalAllocPoint = 0;

    // El número de bloque cuando comienza rewards Eth.
    uint256 public startBlock;

    // Recompensas totales blockeadas
    uint256 public totalLockedUpRewards;

    // Total eth en la pool
    uint256 public totalEthInPools = 0;
    

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(
        address indexed user,
        uint256 indexed pid,
        uint256 amount
    );
    event EmissionRateUpdated(
        address indexed caller,
        uint256 previousAmount,
        uint256 newAmount
    );
    event RewardLockedUp(
        address indexed user,
        uint256 indexed pid,
        uint256 amountLockedUp
    );
    event OperatorTransferred(
        address indexed previousOperator,
        address indexed newOperator
    );
    event DevAddressChanged(
        address indexed caller,
        address oldAddress,
        address newAddress
    );
    event FeeAddressChanged(
        address indexed caller,
        address oldAddress,
        address newAddress
    );
    event AllocPointsUpdated(
        address indexed caller,
        uint256 previousAmount,
        uint256 newAmount
    );
    event MetaTxnsEnabled(address indexed caller);
    event MetaTxnsDisabled(address indexed caller);

modifier onlyOperator() {
        require(
            _operator == msg.sender,
            "Operator: caller is not the operator"
        );
        _;
    }

    constructor(IBank _eth, uint256 _ethPerBlock) {
        //StartBlock siempre muchos años después de la construcción del contrato, se establecerá más tarde en la función StartRewards
        startBlock = block.number + (10 * 365 * 24 * 60 * 60);

        eth = _eth;
        ethPerBlock = _ethPerBlock;

        devAddress = msg.sender;
        feeAddress = msg.sender;
        _operator = msg.sender;
        emit OperatorTransferred(address(0), _operator);
    }

    function isTrustedForwarder(address forwarder)
        public
        view
        virtual
        returns (bool)
    {
        return forwarder == _trustedForwarder;
    }

    function _msgSender()
        internal
        view
        virtual
        override
        returns (address sender)
    {
        if (isTrustedForwarder(msg.sender)) {            
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return super._msgSender();
        }
    }

    function _msgData()
        internal
        view
        virtual
        override
        returns (bytes calldata)
    {
        if (isTrustedForwarder(msg.sender)) {
            return msg.data[:msg.data.length - 20];
        } else {
            return super._msgData();
        }
    }

    function operator() public view returns (address) {
        return _operator;
    }

    function getMultiplier(uint256 _from, uint256 _to)
        public
        pure
        returns (uint256)
    {
        return _to.sub(_from);
    }

    function transferOperator(address newOperator) public onlyOperator {
        require(
            newOperator != address(0),
            "TransferOperator: new operator is the zero address"
        );
        emit OperatorTransferred(_operator, newOperator);
        _operator = newOperator;
    }

    // Set farming start, can call only once
    function startRewards() public onlyOwner {
        require(block.number < startBlock, "Error: rewards started already");

        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            PoolInfo storage pool = poolInfo[pid];
            pool.lastRewardBlock = block.number;
        }

        startBlock = block.number;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    /// Agrega un nuevo token/lp al grupo. Sólo puede ser llamado por el propietario.
    // Puede agregar varios sin estropear las recompensas, porque el saldo de cada uno se rastrea utilizando su propio totalTokens    
    function add(uint256 _allocPoint, IERC20 _token, uint16 _depositFeeBP, uint256 _harvestInterval, bool _withUpdate) public onlyOwner {

        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_RATE, "Add: deposit fee too high");
        require(_harvestInterval <= MAXIMUM_HARVEST_INTERVAL, "Add: invalid harvest interval");
        
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock
        ? block.number
        : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolInfo.push(
                PoolInfo({
                    token: _token,
                    lastRewardBlock: lastRewardBlock,
                    accEthPerShare: 0,
                    depositFeeBP: _depositFeeBP,
                    harvestInterval: _harvestInterval,
                    totalTokens: 0
                    
                    })
        );
    }

    
    // función para ver si el usuario puede recoger ETH.
    function canHarvest(uint256 _pid, address _user)
        public
        view
        returns (bool)
    {
        UserInfo storage user = userInfo[_pid][_user];
        return
            block.number >= startBlock &&
            block.timestamp >= user.nextHarvestUntil;
    }

    // Actualiza variables de pools!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // 
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }

        uint256 lpSupply = pool.totalTokens;
        if (lpSupply == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }

        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 ethReward = multiplier
            .mul(ethPerBlock)
            
            .div(totalAllocPoint);

        eth.mint(devAddress, ethReward.div(10));
        eth.mint(address(this), ethReward);

        pool.accEthPerShare = pool.accEthPerShare.add(
            ethReward.mul(1e12).div(pool.totalTokens)
        );
        pool.lastRewardBlock = block.number;
    }

    // Deposito de tokens
    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {
        require(
            block.number >= startBlock,
            "Deposit: cannot deposit before rewards start"
        );

        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];

        updatePool(_pid);

        payOrLockupPendingEth(_pid);

        if (_amount > 0) {
            uint256 beforeDeposit = pool.token.balanceOf(address(this));
            pool.token.safeTransferFrom(_msgSender(), address(this), _amount);
            uint256 afterDeposit = pool.token.balanceOf(address(this));

            _amount = afterDeposit.sub(beforeDeposit);

            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.token.safeTransfer(feeAddress, depositFee);

                _amount = _amount.sub(depositFee);
            }

            user.amount = user.amount.add(_amount);
            pool.totalTokens = pool.totalTokens.add(_amount);

if (address(pool.token) == address(eth)) {
                totalEthInPools = totalEthInPools.add(_amount);
            }
        }
        user.rewardDebt = user.amount.mul(pool.accEthPerShare).div(1e12);
        user.lastInteraction = block.timestamp;
        emit Deposit(_msgSender(), _pid, _amount);
    }

    // Retiro de tokens
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];

        
        require(user.amount >= _amount, "Withdraw: user amount is not enough");

        
        require(pool.totalTokens >= _amount, "Withdraw: pool total is not enough");

        
        require(
            block.timestamp > user.lastInteraction,
            "Withdraw: you cannot withdraw yet"
        );

        updatePool(_pid);

        payOrLockupPendingEth(_pid);

        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.totalTokens = pool.totalTokens.sub(_amount);
            if (address(pool.token) == address(eth)) {
                totalEthInPools = totalEthInPools.sub(_amount);
            }
            pool.token.safeTransfer(_msgSender(), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accEthPerShare).div(1e12);
        user.lastInteraction = block.timestamp;
        emit Withdraw(_msgSender(), _pid, _amount);
    }

    // Pagos o bloqueos pendientes de eth.
    function payOrLockupPendingEth(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];

        if (user.nextHarvestUntil == 0 && block.number >= startBlock) {
            user.nextHarvestUntil = block.timestamp.add(pool.harvestInterval);
        }

        uint256 pending = user.amount.mul(pool.accEthPerShare).div(1e12).sub(
            user.rewardDebt
        );
        if (canHarvest(_pid, _msgSender())) {
            if (pending > 0 || user.rewardLockedUp > 0) {
                uint256 totalRewards = pending.add(user.rewardLockedUp);

                
                totalLockedUpRewards = totalLockedUpRewards.sub(
                    user.rewardLockedUp
                );
                user.rewardLockedUp = 0;
                user.lastInteraction = block.timestamp;
                user.nextHarvestUntil = block.timestamp.add(
                    pool.harvestInterval
                );

                
                safeEthTransfer(_msgSender(), totalRewards);
            }
        } else if (pending > 0) {
            user.rewardLockedUp = user.rewardLockedUp.add(pending);
            user.lastInteraction = block.timestamp;
            totalLockedUpRewards = totalLockedUpRewards.add(pending);
            emit RewardLockedUp(_msgSender(), _pid, pending);
        }
    }

    // Transfer segura, sin problemas de redondeo.
    function safeEthTransfer(address _to, uint256 _amount) internal {
        if (eth.balanceOf(address(this)) > totalEthInPools) {
            // Se asegura que no se transfieran recompensas de depositos.
            uint256 EthBal = eth.balanceOf(address(this)).sub(
                totalEthInPools
            );
            if (_amount >= EthBal) {
                eth.transfer(_to, EthBal);
            } else if (_amount > 0) {
                eth.transfer(_to, _amount);
            }
        }
    }

    

function setFeeAddress(address _feeAddress) public {
        require(_msgSender() == feeAddress, "setFeeAddress: FORBIDDEN");
        require(_feeAddress != address(0), "setFeeAddress: ZERO");

        emit FeeAddressChanged(_msgSender(), feeAddress, _feeAddress);

        feeAddress = _feeAddress;
    }    

    
}