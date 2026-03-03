const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
    order_id: { type: String, unique: true, required: true },
    order_date: { type: String, required: true },
    customer_name: { type: String, default: '' },
    customer_phone: { type: String, default: '' },
    delivery_address: { type: String, default: '' },
    distance_km: { type: Number, default: 0 },
    items_list: { type: String, default: '' },
    quantities: { type: String, default: '' },
    item_prices: { type: String, default: '' },
    subtotal: { type: Number, default: 0 },
    delivery_charges: { type: Number, default: 0 },
    total_amount: { type: Number, default: 0 },
    payment_method: { type: String, default: '' },
    upi_id: { type: String, default: '' },
    payment_status: { type: String, default: 'Paid' },
    transaction_id: { type: String, default: '' },
    order_status: { type: String, default: 'New' },
    customer_lat: { type: Number, default: null },
    customer_lon: { type: Number, default: null },
    map_link: { type: String, default: '' },
    order_source: { type: String, default: 'WhatsApp' },
    created_at: { type: Date, default: Date.now }
}, {
    timestamps: true
});

module.exports = mongoose.model('Order', orderSchema);
