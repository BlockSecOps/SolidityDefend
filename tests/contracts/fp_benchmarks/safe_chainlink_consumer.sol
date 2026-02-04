// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

/**
 * @title SafeChainlinkConsumer
 * @notice A properly implemented Chainlink oracle consumer with all safety checks.
 * @dev This contract should NOT trigger oracle manipulation vulnerability detectors.
 *
 * Safe patterns implemented:
 * - AggregatorV3Interface usage
 * - Staleness check (updatedAt validation)
 * - Answer > 0 validation
 * - answeredInRound validation
 * - Multi-oracle fallback
 * - Deviation bounds checking
 */
contract SafeChainlinkConsumer {
    AggregatorV3Interface public primaryOracle;
    AggregatorV3Interface public secondaryOracle;

    uint256 public constant MAX_STALENESS = 3600; // 1 hour
    uint256 public constant MAX_DEVIATION = 500; // 5% (basis points)
    uint256 public constant BASIS_POINTS = 10000;

    error StalePrice();
    error InvalidPrice();
    error PriceDeviationTooHigh();
    error InvalidRound();

    constructor(address _primaryOracle, address _secondaryOracle) {
        primaryOracle = AggregatorV3Interface(_primaryOracle);
        secondaryOracle = AggregatorV3Interface(_secondaryOracle);
    }

    /**
     * @notice Get validated price from primary oracle
     * @dev Implements full Chainlink best practices:
     *      - Staleness check
     *      - Zero/negative price check
     *      - answeredInRound validation
     */
    function getPrimaryPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = primaryOracle.latestRoundData();

        // Staleness check
        if (block.timestamp - updatedAt > MAX_STALENESS) {
            revert StalePrice();
        }

        // Price must be positive
        if (answer <= 0) {
            revert InvalidPrice();
        }

        // Round completeness check
        if (answeredInRound < roundId) {
            revert InvalidRound();
        }

        return uint256(answer);
    }

    /**
     * @notice Get validated price from secondary oracle
     */
    function getSecondaryPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = secondaryOracle.latestRoundData();

        // Staleness check
        if (block.timestamp - updatedAt > MAX_STALENESS) {
            revert StalePrice();
        }

        // Price must be positive
        if (answer <= 0) {
            revert InvalidPrice();
        }

        // Round completeness check
        if (answeredInRound < roundId) {
            revert InvalidRound();
        }

        return uint256(answer);
    }

    /**
     * @notice Get validated price with multi-oracle cross-validation
     * @dev Uses both oracles and validates deviation is within bounds
     * @return price The validated price
     */
    function getValidatedPrice() external view returns (uint256 price) {
        uint256 primaryPrice = getPrimaryPrice();
        uint256 secondaryPrice = getSecondaryPrice();

        // Calculate deviation
        uint256 deviation = _calculateDeviation(primaryPrice, secondaryPrice);

        // Ensure prices are within acceptable deviation
        if (deviation > MAX_DEVIATION) {
            revert PriceDeviationTooHigh();
        }

        // Use primary price if validation passes
        price = primaryPrice;
    }

    /**
     * @notice Get price with fallback to secondary oracle
     * @dev If primary fails, try secondary
     */
    function getPriceWithFallback() external view returns (uint256 price) {
        try this.getPrimaryPrice() returns (uint256 primaryPrice) {
            price = primaryPrice;
        } catch {
            // Fallback to secondary oracle
            price = getSecondaryPrice();
        }
    }

    /**
     * @notice Calculate deviation between two prices
     * @param price1 First price
     * @param price2 Second price
     * @return deviation Deviation in basis points
     */
    function _calculateDeviation(uint256 price1, uint256 price2)
        internal
        pure
        returns (uint256 deviation)
    {
        if (price1 == 0 || price2 == 0) {
            return BASIS_POINTS; // Max deviation if either is zero
        }

        uint256 diff = price1 > price2 ? price1 - price2 : price2 - price1;
        deviation = (diff * BASIS_POINTS) / price1;
    }
}
