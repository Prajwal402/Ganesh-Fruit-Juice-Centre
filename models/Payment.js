const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
    paymentToken: { type: String, required: true, unique: true },
    orderNo: { type: String, required: true },
    name: { type: String, required: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    distance: { type: Number, default: 0 },
    items: { type: [String], default: [] },
    itemsDetailed: { type: [mongoose.Schema.Types.Mixed], default: [] },
    subtotal: { type: Number, default: 0 },
    delivery: { type: Number, default: 0 },
    total: { type: Number, default: 0 },
    upiId: { type: String, default: '' },
    location: {
        lat: { type: Number, default: null },
        lon: { type: Number, default: null }
    },
    mapLink: { type: String, default: '' },
    verified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now, expires: 1800 } // Auto-delete after 30 mins
});

module.exports = mongoose.model('Payment', paymentSchema);
