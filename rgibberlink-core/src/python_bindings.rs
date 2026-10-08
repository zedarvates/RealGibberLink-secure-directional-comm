use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::collections::HashMap;
use crate::crypto::{CryptoEngine, CryptoError};
use crate::visual::{VisualEngine, VisualError, VisualPayload};
use crate::audio::AudioEngine;
use crate::protocol::{ProtocolEngine, ProtocolError, ProtocolState};
use crate::RgibberLink;
use qrcode;
use crate::weather::{WeatherManager, WeatherData, WeatherImpact, WindImpact, ConstraintValidationResult, ConstraintViolation, WeatherAdaptation, RiskAssessment, WeatherSource, DroneSpecifications};
use crate::mission::{MissionPayload, MissionHeader, MissionTask, GeoCoordinate};
use crate::audit::{AuditSystem, AuditEntry, SecurityAlert, AuditEventType, AuditSeverity, AuditActor, AuditOperation, create_audit_entry};
use crate::range_detector::{RangeDetector, RangeDetectorError, RangingConfig, RangeMeasurement, RangeDetectorCategory, RangeEnvironmentalConditions};
use crate::laser::{LaserEngine, LaserError, LaserConfig, LaserType, ModulationScheme, AlignmentStatus};
use crate::ultrasonic_beam::{UltrasonicBeamEngine, UltrasonicBeamError, BeamConfig, BeamSignal};
use crate::optical_ecc::{OpticalECC, OpticalECCError, OpticalQualityMetrics, AdaptiveECCConfig};
use crate::channel_validator::{ChannelValidator, ValidationError, ValidationPhase, ChannelData, ChannelType};
use crate::security::{SecurityManager, SecurityError, SecurityConfig, SecurityLevel};
use crate::fallback::{FallbackManager, FallbackError, FallbackConfig};
use crate::performance_monitor::{PerformanceMonitor, PerformanceError, PerformanceMetrics, PerformanceConfig, PerformancePreset};

#[cfg(feature = "post-quantum")]
use pqcrypto_traits::{kem::{PublicKey as _, Ciphertext as _, SharedSecret as _}, sign::{PublicKey as _, DetachedSignature as _}};

/// Keep timers and background tasks alive across synchronous Python calls.
fn block_on<F: std::future::Future>(future: F) -> PyResult<F::Output> {
    static RUNTIME: std::sync::OnceLock<Result<tokio::runtime::Runtime, String>> = std::sync::OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().map_err(|e| e.to_string()));
    let runtime = runtime.as_ref().map_err(|e| PyRuntimeError::new_err(e.clone()))?;
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(PyRuntimeError::new_err("Synchronous bindings cannot run inside a Tokio runtime"));
    }
    Ok(runtime.block_on(future))
}

/// Python wrapper for CryptoEngine
#[pyclass]
pub struct PyCryptoEngine {
    inner: CryptoEngine,
}

#[pymethods]
impl PyCryptoEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: CryptoEngine::new(),
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    fn derive_shared_secret(&mut self, peer_public_key: Vec<u8>) -> PyResult<[u8; 32]> {
        self.inner.derive_shared_secret(&peer_public_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Crypto error: {}", e)))
    }

    #[staticmethod]
    fn encrypt_data(key: Vec<u8>, data: Vec<u8>) -> PyResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(PyRuntimeError::new_err("Key must be 32 bytes"));
        }
        let key_array: [u8; 32] = key.try_into().map_err(|_| PyRuntimeError::new_err("Invalid key length"))?;
        CryptoEngine::encrypt_data(&key_array, &data)
            .map_err(|e| PyRuntimeError::new_err(format!("Encryption error: {}", e)))
    }

    #[staticmethod]
    fn decrypt_data(key: Vec<u8>, encrypted_data: Vec<u8>) -> PyResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(PyRuntimeError::new_err("Key must be 32 bytes"));
        }
        let key_array: [u8; 32] = key.try_into().map_err(|_| PyRuntimeError::new_err("Invalid key length"))?;
        CryptoEngine::decrypt_data(&key_array, &encrypted_data)
            .map_err(|e| PyRuntimeError::new_err(format!("Decryption error: {}", e)))
    }

    #[staticmethod]
    fn generate_secure_random_bytes(length: usize) -> Vec<u8> {
        CryptoEngine::generate_secure_random_bytes(length)
    }

    #[staticmethod]
    fn generate_nonce() -> [u8; 16] {
        CryptoEngine::generate_nonce()
    }
}

/// Python wrapper for VisualEngine
#[pyclass]
pub struct PyVisualEngine {
    inner: VisualEngine,
}

#[pymethods]
impl PyVisualEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: VisualEngine::new(),
        }
    }

    fn encode_payload(&self, payload: &PyVisualPayload) -> PyResult<String> {
        self.inner.encode_payload(&payload.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Visual error: {}", e)))
    }

    fn encode_qr_code(&self, py: Python, data: Vec<u8>) -> PyResult<String> {
        py.detach(|| {
            let code = qrcode::QrCode::new(&data)
                .map_err(|_| PyRuntimeError::new_err("QR code generation failed"))?;
            Ok(code.render::<qrcode::render::svg::Color>().build())
        })
    }

    fn decode_payload(&self, qr_data: Vec<u8>) -> PyResult<PyVisualPayload> {
        let payload = self.inner.decode_payload(&qr_data)
            .map_err(|e| PyRuntimeError::new_err(format!("Visual error: {}", e)))?;
        Ok(PyVisualPayload { inner: payload })
    }
}

/// Python wrapper for VisualPayload
#[pyclass]
#[derive(Clone)]
pub struct PyVisualPayload {
    inner: VisualPayload,
}

#[pymethods]
impl PyVisualPayload {
    #[new]
    fn new(session_id: [u8; 16], public_key: Vec<u8>, nonce: [u8; 16], signature: Vec<u8>) -> Self {
        Self {
            inner: VisualPayload {
                session_id,
                public_key,
                nonce,
                signature,
            },
        }
    }

    #[getter]
    fn session_id(&self) -> [u8; 16] {
        self.inner.session_id
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.clone()
    }

    #[getter]
    fn nonce(&self) -> [u8; 16] {
        self.inner.nonce
    }

    #[getter]
    fn signature(&self) -> Vec<u8> {
        self.inner.signature.clone()
    }
}

/// Python wrapper for AudioEngine
#[pyclass]
pub struct PyAudioEngine {
    inner: AudioEngine,
}

#[pymethods]
impl PyAudioEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: AudioEngine::new(),
        }
    }

    fn send_data(&self, py: Python, data: Vec<u8>) -> PyResult<()> {
        py.detach(|| {
            // For now, return Ok since audio engine is not fully implemented
            Ok(())
        })
    }

    fn receive_data(&self, py: Python) -> PyResult<Vec<u8>> {
        py.detach(|| {
            // For now, return empty data since audio engine is not fully implemented
            Ok(vec![])
        })
    }

    fn is_receiving(&self, py: Python) -> bool {
        py.detach(|| false)
    }
}

/// Python wrapper for ProtocolEngine
#[pyclass]
pub struct PyProtocolEngine {
    inner: ProtocolEngine,
}

#[pymethods]
impl PyProtocolEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: ProtocolEngine::new(),
        }
    }

    fn initiate_handshake(&self, py: Python) -> PyResult<()> {
        py.detach(|| {
            // For now, simulate handshake initiation
            Ok(())
        })
    }

    fn receive_nonce(&self, py: Python, nonce: Vec<u8>) -> PyResult<String> {
        py.detach(|| {
            // For now, return a mock QR code
            Ok("<svg>Mock QR Code</svg>".to_string())
        })
    }

    fn process_qr_payload(&self, py: Python, qr_data: Vec<u8>) -> PyResult<()> {
        py.detach(|| {
            // For now, simulate QR processing
            Ok(())
        })
    }

    fn receive_ack(&self, py: Python) -> PyResult<()> {
        py.detach(|| {
            // For now, simulate ACK reception
            Ok(())
        })
    }

    fn get_state(&self, py: Python) -> PyResult<String> {
        py.detach(|| {
            Ok("idle".to_string())
        })
    }

    fn encrypt_message(&self, py: Python, data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            // For now, return data unchanged (no encryption)
            Ok(data)
        })
    }

    fn decrypt_message(&self, py: Python, encrypted_data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            // For now, return data unchanged (no decryption)
            Ok(encrypted_data)
        })
    }
}

/// Python wrapper for RgibberLink
#[pyclass]
pub struct PyRgibberLink {
    inner: RgibberLink,
}

#[pymethods]
impl PyRgibberLink {
    #[new]
    fn new() -> Self {
        Self {
            inner: RgibberLink::new(),
        }
    }

    fn initiate_handshake(&self, py: Python) -> PyResult<()> {
        py.detach(|| {
            // For now, simulate handshake initiation
            Ok(())
        })
    }

    fn receive_nonce(&self, py: Python, nonce: Vec<u8>) -> PyResult<String> {
        py.detach(|| {
            // For now, return a mock QR code
            Ok("<svg>Mock QR Code</svg>".to_string())
        })
    }

    fn process_qr_payload(&self, py: Python, qr_data: Vec<u8>) -> PyResult<()> {
        py.detach(|| {
            // For now, simulate QR processing
            Ok(())
        })
    }

    fn receive_ack(&self, py: Python) -> PyResult<()> {
        py.detach(|| {
            // For now, simulate ACK reception
            Ok(())
        })
    }

    fn get_state(&self, py: Python) -> PyResult<String> {
        py.detach(|| {
            Ok("idle".to_string())
        })
    }

    fn encrypt_message(&self, py: Python, data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            // For now, return data unchanged (no encryption)
            Ok(data)
        })
    }

    fn decrypt_message(&self, py: Python, encrypted_data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            // For now, return data unchanged (no decryption)
            Ok(encrypted_data)
        })
    }
}

/// Python wrapper for WeatherManager
#[pyclass]
pub struct PyWeatherManager {
    inner: WeatherManager,
}

#[pymethods]
impl PyWeatherManager {
    #[new]
    fn new(max_stations: usize) -> Self {
        Self {
            inner: WeatherManager::new(max_stations),
        }
    }

    fn update_weather(&mut self, weather_data: PyWeatherData) -> PyResult<()> {
        self.inner.update_weather(weather_data.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Weather error: {}", e)))
    }

    fn assess_weather_impact(&self, py: Python, mission: &PyMissionPayload, drone_specs: &PyDroneSpecifications) -> PyResult<PyWeatherImpact> {
        py.detach(|| {
            let impact = self.inner.assess_weather_impact(&mission.inner, &drone_specs.inner)
                .map_err(|e| PyRuntimeError::new_err(format!("Weather assessment error: {}", e)))?;
            Ok(PyWeatherImpact { inner: impact })
        })
    }

    fn validate_mission_constraints(&self, py: Python, mission: &PyMissionPayload, drone_specs: &PyDroneSpecifications) -> PyResult<PyValidationResult> {
        py.detach(|| {
            let result = self.inner.validate_mission_constraints(&mission.inner, &drone_specs.inner)
                .map_err(|e| PyRuntimeError::new_err(format!("Validation error: {}", e)))?;
            Ok(PyValidationResult { inner: result })
        })
    }
}

/// Python wrapper for WeatherData
#[pyclass]
#[derive(Clone)]
pub struct PyWeatherData {
    inner: WeatherData,
}

#[pymethods]
impl PyWeatherData {
    #[new]
    fn new(timestamp: f64, location: PyGeoCoordinate, temperature_celsius: f32, humidity_percent: f32,
           wind_speed_mps: f32, wind_direction_degrees: f32, gust_speed_mps: f32, visibility_meters: f32,
           precipitation_rate_mmh: f32, pressure_hpa: f32, cloud_cover_percent: f32, lightning_probability: f32) -> Self {
        Self {
            inner: WeatherData {
                timestamp: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs_f64(timestamp),
                location: location.inner,
                temperature_celsius,
                humidity_percent,
                wind_speed_mps,
                wind_direction_degrees,
                gust_speed_mps,
                visibility_meters,
                precipitation_type: None, // Not provided in constructor
                precipitation_rate_mmh,
                pressure_hpa,
                cloud_cover_percent,
                lightning_probability,
                source: WeatherSource::WeatherAPI, // Default
                forecast_horizon_hours: Some(6), // Default
            },
        }
    }
}

/// Python wrapper for GeoCoordinate
#[pyclass]
#[derive(Clone)]
pub struct PyGeoCoordinate {
    inner: GeoCoordinate,
}

#[pymethods]
impl PyGeoCoordinate {
    #[new]
    fn new(latitude: f64, longitude: f64, altitude_msl: f32) -> Self {
        Self {
            inner: GeoCoordinate {
                latitude,
                longitude,
                altitude_msl,
            },
        }
    }
}

/// Python wrapper for WeatherImpact
#[pyclass]
#[derive(Clone)]
pub struct PyWeatherImpact {
    inner: WeatherImpact,
}

#[pymethods]
impl PyWeatherImpact {
    #[getter]
    fn overall_risk_score(&self) -> f32 {
        self.inner.overall_risk_score
    }

    #[getter]
    fn wind_impact(&self) -> PyWindImpact {
        PyWindImpact { inner: self.inner.wind_impact.clone() }
    }

    #[getter]
    fn recommended_actions(&self) -> Vec<String> {
        self.inner.recommended_actions.clone()
    }
}

/// Python wrapper for WindImpact
#[pyclass]
#[derive(Clone)]
pub struct PyWindImpact {
    inner: WindImpact,
}

#[pymethods]
impl PyWindImpact {
    #[getter]
    fn track_deviation_degrees(&self) -> f32 {
        self.inner.track_deviation_degrees
    }

    #[getter]
    fn increased_power_draw_w(&self) -> f32 {
        self.inner.increased_power_draw_w
    }

    #[getter]
    fn reduced_endurance_percent(&self) -> f32 {
        self.inner.reduced_endurance_percent
    }

    #[getter]
    fn abort_threshold_exceeded(&self) -> bool {
        self.inner.abort_threshold_exceeded
    }
}

/// Python wrapper for ConstraintValidationResult
#[pyclass]
#[derive(Clone)]
pub struct PyValidationResult {
    inner: ConstraintValidationResult,
}

#[pymethods]
impl PyValidationResult {
    #[getter]
    fn is_valid(&self) -> bool {
        self.inner.is_valid
    }

    #[getter]
    fn violations(&self) -> Vec<PyConstraintViolation> {
        self.inner.violations.iter().map(|v| PyConstraintViolation { inner: v.clone() }).collect()
    }

    #[getter]
    fn weather_adaptations(&self) -> Vec<PyWeatherAdaptation> {
        self.inner.weather_adaptations.iter().map(|a| PyWeatherAdaptation { inner: a.clone() }).collect()
    }

    #[getter]
    fn risk_assessment(&self) -> PyRiskAssessment {
        PyRiskAssessment { inner: self.inner.risk_assessment.clone() }
    }
}

/// Python wrapper for ConstraintViolation
#[pyclass]
#[derive(Clone)]
pub struct PyConstraintViolation {
    inner: ConstraintViolation,
}

#[pymethods]
impl PyConstraintViolation {
    #[getter]
    fn constraint_type(&self) -> String {
        format!("{:?}", self.inner.constraint_type)
    }

    #[getter]
    fn description(&self) -> String {
        self.inner.description.clone()
    }
}

/// Python wrapper for WeatherAdaptation
#[pyclass]
#[derive(Clone)]
pub struct PyWeatherAdaptation {
    inner: WeatherAdaptation,
}

#[pymethods]
impl PyWeatherAdaptation {
    #[getter]
    fn description(&self) -> String {
        self.inner.description.clone()
    }
}

/// Python wrapper for RiskAssessment
#[pyclass]
#[derive(Clone)]
pub struct PyRiskAssessment {
    inner: RiskAssessment,
}

#[pymethods]
impl PyRiskAssessment {
    #[getter]
    fn overall_risk_level(&self) -> String {
        format!("{:?}", self.inner.overall_risk_level)
    }

    #[getter]
    fn confidence_score(&self) -> f32 {
        self.inner.confidence_score
    }
}

/// Python wrapper for MissionPayload
#[pyclass]
#[derive(Clone)]
pub struct PyMissionPayload {
    inner: MissionPayload,
}

#[pymethods]
impl PyMissionPayload {
    #[new]
    fn new(name: String, mission_id: [u8; 16]) -> Self {
        let mut mission = MissionPayload::default();
        mission.header.id = mission_id;
        mission.header.name = name;
        Self { inner: mission }
    }

    #[getter]
    fn header(&self) -> PyMissionHeader {
        PyMissionHeader { inner: self.inner.header.clone() }
    }

    #[getter]
    fn tasks(&self) -> Vec<PyMissionTask> {
        self.inner.tasks.iter().map(|t| PyMissionTask { inner: t.clone() }).collect()
    }
}

/// Python wrapper for MissionHeader
#[pyclass]
#[derive(Clone)]
pub struct PyMissionHeader {
    inner: MissionHeader,
}

#[pymethods]
impl PyMissionHeader {
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[getter]
    fn priority(&self) -> String {
        format!("{:?}", self.inner.priority)
    }
}

/// Python wrapper for MissionTask
#[pyclass]
#[derive(Clone)]
pub struct PyMissionTask {
    inner: MissionTask,
}

#[pymethods]
impl PyMissionTask {
    #[getter]
    fn label(&self) -> String {
        self.inner.label.clone()
    }

    #[getter]
    fn sequence_order(&self) -> u32 {
        self.inner.sequence_order
    }
}

/// Python wrapper for DroneSpecifications
#[pyclass]
#[derive(Clone)]
pub struct PyDroneSpecifications {
    inner: DroneSpecifications,
}

#[pymethods]
impl PyDroneSpecifications {
    #[new]
    fn new(max_wind_speed_mps: f32, max_speed_mps: f32, abort_gust_threshold_mps: f32, power_wind_coefficient: f32, mass_kg: f32, battery_capacity_wh: f32, sensor_count: usize) -> Self {
        Self {
            inner: DroneSpecifications {
                max_wind_speed_mps,
                max_speed_mps,
                abort_gust_threshold_mps,
                power_wind_coefficient,
                mass_kg,
                battery_capacity_wh,
                sensor_types: vec!["sensor".to_string(); sensor_count], // Placeholder
            },
        }
    }
}

/// Python wrapper for AuditSystem
#[pyclass]
pub struct PyAuditSystem {
    inner: AuditSystem,
}

#[pymethods]
impl PyAuditSystem {
    #[new]
    fn new(max_entries: usize) -> Self {
        Self {
            inner: AuditSystem::new(max_entries),
        }
    }

    fn record_event(&mut self, py: Python, event: PyAuditEntry) -> PyResult<String> {
        py.detach(|| {
            self.inner.record_event(event.inner)
                .map_err(|e| PyRuntimeError::new_err(format!("Audit error: {}", e)))
        })
    }

    fn get_active_alerts(&self) -> Vec<PySecurityAlert> {
        self.inner.get_active_alerts().iter().map(|a| PySecurityAlert { inner: (*a).clone() }).collect()
    }
}

/// Python wrapper for AuditEntry
#[pyclass]
#[derive(Clone)]
pub struct PyAuditEntry {
    inner: AuditEntry,
}

#[pymethods]
impl PyAuditEntry {
    #[new]
    fn new(event_type: String, severity: String, actor: String, operation: String, success: bool) -> Self {
        // Simplified constructor - would need full implementation
        let audit_entry = create_audit_entry(
            match event_type.as_str() {
                "MissionTransfer" => AuditEventType::MissionTransfer,
                _ => AuditEventType::MissionTransfer,
            },
            match severity.as_str() {
                "High" => AuditSeverity::High,
                _ => AuditSeverity::Medium,
            },
            match actor.as_str() {
                "Operator" => AuditActor::HumanOperator {
                    operator_id: "operator_1".to_string(),
                    clearance_level: "standard".to_string(),
                    department: None,
                },
                _ => AuditActor::System {
                    component: "unknown".to_string(),
                    version: "1.0".to_string(),
                    subsystem: "mission".to_string(),
                },
            },
            AuditOperation {
                operation_type: "mission".to_string(),
                operation_name: operation,
                parameters: HashMap::new(),
                execution_context: crate::audit::OperationContext::default(),
                expected_duration: None,
                resource_consumption: crate::audit::ResourceConsumption::default(),
            },
            crate::audit::OperationResult {
                success,
                error_code: None,
                error_message: None,
                duration_ms: 100,
                performance_metrics: crate::audit::PerformanceMetrics::default(),
                side_effects: vec![],
            },
            crate::audit::AuditContext::default(),
        );

        Self { inner: audit_entry }
    }
}

/// Python wrapper for SecurityAlert
#[pyclass]
#[derive(Clone)]
pub struct PySecurityAlert {
    inner: SecurityAlert,
}

#[pymethods]
impl PySecurityAlert {
    #[getter]
    fn severity(&self) -> String {
        format!("{:?}", self.inner.severity)
    }

    #[getter]
    fn title(&self) -> String {
        self.inner.title.clone()
    }
}

/// Python wrapper for RangeDetector
#[pyclass]
pub struct PyRangeDetector {
    inner: std::sync::Arc<tokio::sync::Mutex<RangeDetector>>,
}

#[pymethods]
impl PyRangeDetector {
    #[new]
    fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(tokio::sync::Mutex::new(RangeDetector::new())),
        }
    }

    fn initialize(&mut self, py: Python) -> PyResult<()> {
        py.detach(|| {
            block_on(async { self.inner.lock().await.initialize().await })?
                .map_err(|e| PyRuntimeError::new_err(format!("Range detector initialization error: {}", e)))
        })
    }

    fn measure_distance(&self, py: Python) -> PyResult<PyRangeMeasurement> {
        py.detach(|| {
            let measurement = block_on(async { self.inner.lock().await.measure_distance().await })?
                .map_err(|e| PyRuntimeError::new_err(format!("Range measurement error: {}", e)))?;
            Ok(PyRangeMeasurement { inner: measurement })
        })
    }

    fn measure_distance_averaged(&self, py: Python, samples: usize) -> PyResult<PyRangeMeasurement> {
        py.detach(|| {
            let measurement = block_on(async { self.inner.lock().await.measure_distance_averaged_with_samples(samples).await })?
                .map_err(|e| PyRuntimeError::new_err(format!("Averaged range measurement error: {}", e)))?;
            Ok(PyRangeMeasurement { inner: measurement })
        })
    }

    fn update_environmental_conditions(&self, py: Python, conditions: PyRangeEnvironmentalConditions) -> PyResult<()> {
        py.detach(|| {
            block_on(async { self.inner.lock().await.update_environmental_conditions(conditions.inner).await })?;
            Ok(())
        })
    }

    fn get_current_range_category(&self, py: Python) -> PyResult<String> {
        py.detach(|| {
            let category = block_on(async { self.inner.lock().await.get_current_range_category().await })?
                .map(|cat| format!("{:?}", cat))
                .unwrap_or("Unknown".to_string());
            Ok(category)
        })
    }
}

/// Python wrapper for RangeMeasurement
#[pyclass]
#[derive(Clone)]
pub struct PyRangeMeasurement {
    inner: RangeMeasurement,
}

#[pymethods]
impl PyRangeMeasurement {
    #[getter]
    fn distance_m(&self) -> f32 {
        self.inner.distance_m
    }

    #[getter]
    fn signal_strength(&self) -> f32 {
        self.inner.signal_strength
    }

    #[getter]
    fn quality_score(&self) -> f32 {
        self.inner.quality_score
    }

    #[getter]
    fn timestamp(&self) -> f64 {
        std::time::SystemTime::now().checked_sub(self.inner.timestamp.elapsed())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .unwrap_or_default().as_secs_f64()
    }
}

/// Python wrapper for RangeEnvironmentalConditions
#[pyclass]
#[derive(Clone)]
pub struct PyRangeEnvironmentalConditions {
    inner: RangeEnvironmentalConditions,
}

#[pymethods]
impl PyRangeEnvironmentalConditions {
    #[new]
    fn new(temperature_celsius: f32, humidity_percent: f32, pressure_hpa: f32, wind_speed_mps: f32, visibility_meters: f32) -> Self {
        Self {
            inner: RangeEnvironmentalConditions {
                temperature_celsius,
                humidity_percent,
                pressure_hpa,
                wind_speed_mps,
                visibility_meters,
            },
        }
    }
}

/// Python wrapper for LaserEngine
#[pyclass]
pub struct PyLaserEngine {
    inner: LaserEngine,
}

#[pymethods]
impl PyLaserEngine {
    #[new]
    fn new(laser_type: String, modulation_scheme: String, max_power_mw: f32, range_meters: f32) -> PyResult<Self> {
        let laser_config = LaserConfig {
            laser_type: match laser_type.as_str() {
                "Visible" => LaserType::Visible,
                "IR" => LaserType::Infrared,
                _ => return Err(PyRuntimeError::new_err("Invalid laser type")),
            },
            modulation: match modulation_scheme.as_str() {
                "OOK" => ModulationScheme::Ook,
                "PWM" => ModulationScheme::Pwm,
                "QR" => ModulationScheme::QrProjection,
                _ => return Err(PyRuntimeError::new_err("Invalid modulation scheme")),
            },
            max_power_mw,
            range_meters,
            ..Default::default()
        };

        let rx_config = crate::laser::ReceptionConfig::default();

        Ok(Self {
            inner: LaserEngine::new(laser_config, rx_config),
        })
    }

    fn initialize(&mut self, py: Python) -> PyResult<()> {
        py.detach(|| {
            block_on(self.inner.initialize())?
                .map_err(|e| PyRuntimeError::new_err(format!("Laser initialization error: {}", e)))
        })
    }

    fn transmit_data(&mut self, py: Python, data: Vec<u8>) -> PyResult<()> {
        py.detach(|| {
            block_on(self.inner.transmit_data(&data))?
                .map_err(|e| PyRuntimeError::new_err(format!("Laser transmission error: {}", e)))
        })
    }

    fn enable_adaptive_mode(&mut self, py: Python, range_detector: PyRef<'_, PyRangeDetector>) -> PyResult<()> {
        let detector = range_detector.inner.clone();
        py.detach(|| {
            self.inner.enable_adaptive_mode(detector);
            Ok(())
        })
    }

    fn get_alignment_status(&self, py: Python) -> PyResult<PyAlignmentStatus> {
        py.detach(|| {
            let status = block_on(self.inner.get_alignment_status())?;
            Ok(PyAlignmentStatus { inner: status })
        })
    }
}

/// Python wrapper for AlignmentStatus
#[pyclass]
#[derive(Clone)]
pub struct PyAlignmentStatus {
    inner: AlignmentStatus,
}

#[pymethods]
impl PyAlignmentStatus {
    #[getter]
    fn is_aligned(&self) -> bool {
        self.inner.is_aligned
    }

    #[getter]
    fn beam_position_x(&self) -> f32 {
        self.inner.beam_position_x
    }

    #[getter]
    fn beam_position_y(&self) -> f32 {
        self.inner.beam_position_y
    }
}

/// Python wrapper for UltrasonicBeamEngine
#[pyclass]
pub struct PyUltrasonicBeamEngine {
    inner: UltrasonicBeamEngine,
}

#[pymethods]
impl PyUltrasonicBeamEngine {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: UltrasonicBeamEngine::new(),
        })
    }

    fn initialize(&mut self, py: Python) -> PyResult<()> {
        py.detach(|| {
            block_on(self.inner.initialize())?
                .map_err(|e| PyRuntimeError::new_err(format!("Ultrasonic beam initialization error: {}", e)))
        })
    }

    fn transmit_sync_pulse(&self, py: Python, pattern: Vec<u8>) -> PyResult<()> {
        py.detach(|| {
            block_on(self.inner.transmit_sync_pulse(&pattern))?
                .map_err(|e| PyRuntimeError::new_err(format!("Sync pulse transmission error: {}", e)))
        })
    }

    fn detect_presence(&self, py: Python) -> PyResult<bool> {
        py.detach(|| {
            block_on(self.inner.detect_presence())?
                .map_err(|e| PyRuntimeError::new_err(format!("Presence detection error: {}", e)))
        })
    }
}

/// Python wrapper for OpticalECC
#[pyclass]
pub struct PyOpticalECC {
    inner: OpticalECC,
}

#[pymethods]
impl PyOpticalECC {
    #[new]
    fn new() -> Self {
        Self {
            inner: OpticalECC::new(AdaptiveECCConfig::default()),
        }
    }

    fn encode(&mut self, py: Python, data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            block_on(self.inner.encode(&data))?
                .map_err(|e| PyRuntimeError::new_err(format!("Optical ECC encoding error: {}", e)))
        })
    }

    fn decode(&mut self, py: Python, data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            block_on(self.inner.decode(&data))?
                .map_err(|e| PyRuntimeError::new_err(format!("Optical ECC decoding error: {}", e)))
        })
    }
}

/// Python wrapper for ChannelValidator
#[pyclass]
pub struct PyChannelValidator {
    inner: ChannelValidator,
}

#[pymethods]
impl PyChannelValidator {
    #[new]
    fn new() -> Self {
        Self {
            inner: ChannelValidator::new(),
        }
    }

    fn receive_channel_data(&self, py: Python, data: PyChannelData) -> PyResult<()> {
        py.detach(|| {
            block_on(self.inner.receive_channel_data(data.inner))?
                .map_err(|e| PyRuntimeError::new_err(format!("Channel validation error: {}", e)))
        })
    }
}

/// Python wrapper for ChannelData
#[pyclass]
#[derive(Clone)]
pub struct PyChannelData {
    inner: ChannelData,
}

#[pymethods]
impl PyChannelData {
    #[new]
    fn new(channel_type: String, data: Vec<u8>, timestamp: f64, sequence_id: u64) -> PyResult<Self> {
        let channel_type_enum = match channel_type.as_str() {
            "Laser" => ChannelType::Laser,
            "Ultrasound" => ChannelType::Ultrasound,
            _ => return Err(PyRuntimeError::new_err("Invalid channel type")),
        };

        let epoch_duration = std::time::Duration::try_from_secs_f64(timestamp)
            .map_err(|_| PyRuntimeError::new_err("Invalid timestamp"))?;
        let wall_time = std::time::UNIX_EPOCH.checked_add(epoch_duration)
            .ok_or_else(|| PyRuntimeError::new_err("Timestamp out of range"))?;
        let age = std::time::SystemTime::now().duration_since(wall_time)
            .map_err(|_| PyRuntimeError::new_err("Future timestamps are not allowed"))?;
        let instant = tokio::time::Instant::now().checked_sub(age)
            .ok_or_else(|| PyRuntimeError::new_err("Timestamp out of range"))?;
        Ok(Self {
            inner: ChannelData {
                channel_type: channel_type_enum,
                data,
                timestamp: instant,
                sequence_id,
            },
        })
    }
}

/// Python wrapper for SecurityManager
#[pyclass]
pub struct PySecurityManager {
    inner: SecurityManager,
}

#[pymethods]
impl PySecurityManager {
    #[new]
    fn new(security_level: String) -> PyResult<Self> {
        let level = match security_level.as_str() {
            "Minimum" => SecurityLevel::Minimum,
            "SensitiveEscalation" => SecurityLevel::SensitiveEscalation,
            "Locked" => SecurityLevel::Locked,
            _ => return Err(PyRuntimeError::new_err("Invalid security level")),
        };

        let config = SecurityConfig {
            security_level: level,
            ..Default::default()
        };

        Ok(Self {
            inner: SecurityManager::new(config),
        })
    }

    fn validate_pin(&self, py: Python, pin: String) -> PyResult<()> {
        py.detach(|| {
            block_on(self.inner.validate_pin(&pin))?
                .map_err(|e| PyRuntimeError::new_err(format!("PIN validation error: {}", e)))
        })
    }

    fn check_permission(&self, py: Python, permission: String, scope: String) -> PyResult<()> {
        py.detach(|| {
            let perm_type = match permission.as_str() {
                "Discussion" => crate::security::PermissionType::Discussion,
                "AccessAuth" => crate::security::PermissionType::AccessAuth,
                "Command" => crate::security::PermissionType::Command,
                "Pairing" => crate::security::PermissionType::Pairing,
                "FileTransfer" => crate::security::PermissionType::FileTransfer,
                _ => return Err(PyRuntimeError::new_err("Invalid permission type")),
            };

            let perm_scope = match scope.as_str() {
                "Single" => crate::security::PermissionScope::Single,
                "Group" => crate::security::PermissionScope::Group,
                "All" => crate::security::PermissionScope::All,
                "Session" => crate::security::PermissionScope::Session,
                _ => return Err(PyRuntimeError::new_err("Invalid permission scope")),
            };

            block_on(self.inner.check_permission(perm_type, perm_scope))?
                .map_err(|e| PyRuntimeError::new_err(format!("Permission check error: {}", e)))
        })
    }
}

/// Python wrapper for PerformanceMonitor
#[pyclass]
pub struct PyPerformanceMonitor {
    inner: PerformanceMonitor,
}

#[pymethods]
impl PyPerformanceMonitor {
    #[new]
    fn new(max_history: usize) -> Self {
        Self {
            inner: PerformanceMonitor::new(max_history),
        }
    }

    fn run_benchmark_suite(&self, py: Python, duration_secs: u64) -> PyResult<Vec<PyBenchmarkResult>> {
        py.detach(|| {
            let results = block_on(self.inner.run_benchmark_suite(duration_secs))?
                .map_err(|e| PyRuntimeError::new_err(format!("Benchmark error: {}", e)))?;
            Ok(results.into_iter().map(|r| PyBenchmarkResult { inner: r }).collect())
        })
    }

    fn get_current_metrics(&self, py: Python) -> PyResult<Option<PyPerformanceMetrics>> {
        py.detach(|| {
            let metrics = block_on(self.inner.get_current_metrics())?;
            Ok(metrics.map(|m| PyPerformanceMetrics { inner: m }))
        })
    }
}

/// Python wrapper for BenchmarkResult
#[pyclass]
#[derive(Clone)]
pub struct PyBenchmarkResult {
    inner: crate::performance_monitor::BenchmarkResult,
}

#[pymethods]
impl PyBenchmarkResult {
    #[getter]
    fn benchmark_type(&self) -> String {
        format!("{:?}", self.inner.config.modulation_scheme)
    }

    #[getter]
    fn throughput_mbps(&self) -> f64 {
        self.inner.metrics.data_throughput_bps / 1_000_000.0
    }

    #[getter]
    fn latency_ms(&self) -> f64 {
        self.inner.metrics.handshake_latency_ms
    }
}

/// Python wrapper for PerformanceMetrics
#[pyclass]
#[derive(Clone)]
pub struct PyPerformanceMetrics {
    inner: PerformanceMetrics,
}

#[pymethods]
impl PyPerformanceMetrics {
    #[getter]
    fn throughput_mbps(&self) -> f64 {
        self.inner.data_throughput_bps / 1_000_000.0
    }

    #[getter]
    fn latency_ms(&self) -> f64 {
        self.inner.handshake_latency_ms
    }

}

/// Python wrapper for PostQuantumEngine
#[cfg(feature = "post-quantum")]
#[pyclass]
pub struct PyPostQuantumEngine {
    inner: crate::post_quantum::PostQuantumEngine,
}

#[cfg(feature = "post-quantum")]
#[pymethods]
impl PyPostQuantumEngine {
    #[new]
    fn new() -> PyResult<Self> {
        let engine = crate::post_quantum::PostQuantumEngine::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Post-quantum engine error: {}", e)))?;
        Ok(Self { inner: engine })
    }

    fn kyber_public_key(&self) -> Vec<u8> {
        self.inner.kyber_public_key().as_bytes().to_vec()
    }

    fn dilithium_public_key(&self) -> Vec<u8> {
        self.inner.dilithium_public_key().as_bytes().to_vec()
    }

    fn encapsulate_secret(&self, py: Python, peer_public_key: Vec<u8>) -> PyResult<PyKyberCiphertextData> {
        py.detach(|| {
            let pk = crate::post_quantum::KyberPublicKey::from_bytes(&peer_public_key)
                .map_err(|_| PyRuntimeError::new_err("Invalid Kyber public key"))?;

            let ciphertext_data = self.inner.encapsulate_secret(&pk)
                .map_err(|e| PyRuntimeError::new_err(format!("Encapsulation error: {}", e)))?;

            Ok(PyKyberCiphertextData { inner: ciphertext_data })
        })
    }

    fn decapsulate_secret(&self, py: Python, ciphertext: PyKyberCiphertextData) -> PyResult<Vec<u8>> {
        py.detach(|| {
            let shared_secret = self.inner.decapsulate_secret(&ciphertext.inner.ciphertext)
                .map_err(|e| PyRuntimeError::new_err(format!("Decapsulation error: {}", e)))?;
            Ok(shared_secret.as_bytes().to_vec())
        })
    }

    fn sign_data(&self, py: Python, data: Vec<u8>) -> PyResult<Vec<u8>> {
        py.detach(|| {
            let signature = self.inner.sign_data(&data)
                .map_err(|e| PyRuntimeError::new_err(format!("Signing error: {}", e)))?;
            Ok(signature.as_bytes().to_vec())
        })
    }

    fn verify_signature(&self, py: Python, data: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> PyResult<bool> {
        py.detach(|| {
            let sig = crate::post_quantum::DilithiumSignature::from_bytes(&signature)
                .map_err(|_| PyRuntimeError::new_err("Invalid Dilithium signature"))?;

            let pk = crate::post_quantum::DilithiumPublicKey::from_bytes(&public_key)
                .map_err(|_| PyRuntimeError::new_err("Invalid Dilithium public key"))?;

            self.inner.verify_signature(&data, &sig, &pk)
                .map_err(|e| PyRuntimeError::new_err(format!("Verification error: {}", e)))
        })
    }
}

/// Python wrapper for KyberCiphertextData
#[cfg(feature = "post-quantum")]
#[pyclass]
#[derive(Clone)]
pub struct PyKyberCiphertextData {
    inner: crate::post_quantum::KyberCiphertextData,
}

#[cfg(feature = "post-quantum")]
#[pymethods]
impl PyKyberCiphertextData {
    #[getter]
    fn ciphertext(&self) -> Vec<u8> {
        self.inner.ciphertext.as_bytes().to_vec()
    }

    #[getter]
    fn shared_secret(&self) -> Vec<u8> {
        self.inner.shared_secret.as_bytes().to_vec()
    }
}

/// Main Python module
#[pymodule]
#[pyo3(name = "_core")]
fn gibberlink_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core cryptographic and protocol components
    m.add_class::<PyCryptoEngine>()?;
    m.add_class::<PyVisualEngine>()?;
    m.add_class::<PyVisualPayload>()?;
    m.add_class::<PyAudioEngine>()?;
    m.add_class::<PyProtocolEngine>()?;
    m.add_class::<PyRgibberLink>()?;

    // Range detection and laser communication
    m.add_class::<PyRangeDetector>()?;
    m.add_class::<PyRangeMeasurement>()?;
    m.add_class::<PyRangeEnvironmentalConditions>()?;
    m.add_class::<PyLaserEngine>()?;
    m.add_class::<PyAlignmentStatus>()?;
    m.add_class::<PyUltrasonicBeamEngine>()?;
    m.add_class::<PyOpticalECC>()?;

    // Channel validation and security
    m.add_class::<PyChannelValidator>()?;
    m.add_class::<PyChannelData>()?;
    m.add_class::<PySecurityManager>()?;

    // Performance monitoring
    m.add_class::<PyPerformanceMonitor>()?;
    m.add_class::<PyBenchmarkResult>()?;
    m.add_class::<PyPerformanceMetrics>()?;

    // Post-quantum cryptography
    #[cfg(feature = "post-quantum")]
    {
        m.add_class::<PyPostQuantumEngine>()?;
        m.add_class::<PyKyberCiphertextData>()?;
    }

    // Weather and mission management
    m.add_class::<PyWeatherManager>()?;
    m.add_class::<PyWeatherData>()?;
    m.add_class::<PyGeoCoordinate>()?;
    m.add_class::<PyWeatherImpact>()?;
    m.add_class::<PyWindImpact>()?;
    m.add_class::<PyValidationResult>()?;
    m.add_class::<PyConstraintViolation>()?;
    m.add_class::<PyWeatherAdaptation>()?;
    m.add_class::<PyRiskAssessment>()?;
    m.add_class::<PyMissionPayload>()?;
    m.add_class::<PyMissionHeader>()?;
    m.add_class::<PyMissionTask>()?;
    m.add_class::<PyDroneSpecifications>()?;

    // Audit and compliance
    m.add_class::<PyAuditSystem>()?;
    m.add_class::<PyAuditEntry>()?;
    m.add_class::<PySecurityAlert>()?;

    Ok(())
}
